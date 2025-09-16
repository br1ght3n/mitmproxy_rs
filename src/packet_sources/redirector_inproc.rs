use anyhow::{anyhow, Context, Result};
use prost::Message;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::Duration;
use std::{collections::HashMap, thread};
use std::net::SocketAddr;

use internet_packet::{ConnectionId, InternetPacket, TransportProtocol};
use log::{debug, error, info, warn};
use lru_time_cache::LruCache;
use crate::intercept_conf::{InterceptConf, ProcessInfo};
use crate::ipc;
use crate::ipc::FromProxy;
use crate::processes::get_process_name;
use crate::MAX_PACKET_SIZE;
use prost::bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use windivert::address::WinDivertAddress;
use windivert::prelude::*;

#[derive(Debug)]
enum Event {
    NetworkPacket(WinDivertAddress<NetworkLayer>, Vec<u8>),
    SocketInfo(WinDivertAddress<SocketLayer>),
    Ipc(ipc::from_proxy::Message),
}

#[derive(Debug)]
enum ConnectionState {
    Known(ConnectionAction),
    Unknown(Vec<(WinDivertAddress<NetworkLayer>, InternetPacket)>),
}

#[derive(Debug, Clone)]
enum ConnectionAction {
    None,
    Intercept(ProcessInfo),
}

struct ActiveListeners(HashMap<(std::net::SocketAddr, internet_packet::TransportProtocol), ProcessInfo>);

impl ActiveListeners {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(
        &mut self,
        mut socket: std::net::SocketAddr,
        protocol: internet_packet::TransportProtocol,
        process_info: ProcessInfo,
    ) -> Option<ProcessInfo> {
        if socket.ip() == std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED) {
            socket.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        }
        self.0.insert((socket, protocol), process_info)
    }

    pub fn remove(
        &mut self,
        mut socket: std::net::SocketAddr,
        protocol: internet_packet::TransportProtocol,
    ) -> Option<ProcessInfo> {
        if socket.ip() == std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED) {
            socket.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        }
        self.0.remove(&(socket, protocol))
    }

    pub fn get(&self, mut socket: std::net::SocketAddr, protocol: internet_packet::TransportProtocol) -> Option<&ProcessInfo> {
        if !self.0.contains_key(&(socket, protocol)) {
            socket.set_ip(std::net::Ipv4Addr::UNSPECIFIED.into());
        }
        self.0.get(&(socket, protocol))
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}

/// Run the redirector logic in-process.
/// - `ipc_stream` is a bidirectional stream used as the IPC channel (replaces named pipe client).
/// - `ipc_rx` receives packets that should be written to the redirector's IPC (i.e. packets to inject).
/// - `resource_dir` is an optional path where WinDivert/related resources live.
pub async fn run_inproc<T>(
    ipc_stream: T,
    _resource_dir: Option<PathBuf>,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Similar to redirector main: open WinDivert handles, spawn relay threads, then run an ipc handler.
    let socket_handle = WinDivert::socket(
        "tcp || udp",
        1041,
        WinDivertFlags::new().set_recv_only().set_sniff(),
    )?;
    let wd_net_filter = "!loopback && ((ip && remoteAddr < 224.0.0.0) || (ipv6 && remoteAddr < ff00::)) && (tcp || udp)";
    let network_handle = WinDivert::network(wd_net_filter, 1040, WinDivertFlags::new())?;
    let inject_handle = WinDivert::network("false", 1039, WinDivertFlags::new().set_send_only())?;

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<Event>();

    // Spawn relay threads for WinDivert events
    let tx_clone = event_tx.clone();
    thread::spawn(move || relay_socket_events(socket_handle, tx_clone));
    let tx_clone = event_tx.clone();
    thread::spawn(move || relay_network_events(network_handle, tx_clone));

    // initial state
    let mut state = InterceptConf::disabled();
    event_tx.send(Event::Ipc(ipc::from_proxy::Message::InterceptConf(state.clone().into())))?;

    // Split the IPC stream into a read half (for incoming messages) and a write half
    // (for sending PacketWithMeta back to mitmproxy). Spawn a task to read incoming
    // messages and feed them into the event channel.
    let (reader, mut writer) = tokio::io::split(ipc_stream);
    let tx_ipc = event_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_ipc(reader, tx_ipc).await {
            error!("Error handling IPC: {}", e);
            std::process::exit(1);
        }
    });

    let mut connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(Duration::from_secs(60 * 10));
    let mut active_listeners = ActiveListeners::new();

    loop {
        // let t1 = std::time::Instant::now();
        let result = event_rx.recv().await.unwrap();
        // let t2 = std::time::Instant::now();
        // if (t2 - t1).as_millis() > 10 {
        //     log::warn!("event_rx.recv() waited {} ms", (t2 - t1).as_millis());
        // }
        match result {
            Event::NetworkPacket(address, data) => {
                let packet = match InternetPacket::try_from(data) {
                    Ok(p) => p,
                    Err(e) => {
                        debug!("Error parsing packet: {:?}", e);
                        continue;
                    }
                };

                debug!(
                    "Received packet: {} {} {}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    packet.payload().len()
                );

                let is_multicast = packet.src_ip().is_multicast() || packet.dst_ip().is_multicast();
                let is_loopback_only = packet.src_ip().is_loopback() && packet.dst_ip().is_loopback();
                if is_multicast || is_loopback_only {
                    debug!("skipping multicast={} loopback={}", is_multicast, is_loopback_only);
                    inject_handle.send(&WinDivertPacket { address, data: packet.inner().into() })?;
                    continue;
                }

                match connections.get_mut(&packet.connection_id()) {
                    Some(state) => match state {
                        ConnectionState::Known(s) => {
                            process_packet(address, packet, s, &inject_handle, &mut writer).await?;
                        }
                        ConnectionState::Unknown(packets) => {
                            packets.push((address, packet));
                        }
                    },
                    None => {
                        if address.outbound() {
                            debug!("Adding unknown packet: {}", packet.connection_id());
                            connections.insert(packet.connection_id(), ConnectionState::Unknown(vec![(address, packet)]));
                        } else {
                            let action = {
                                if let Some(proc_info) = active_listeners.get(packet.dst(), packet.protocol()) {
                                    debug!("Inbound packet for known application: {:?} ({})", &proc_info.process_name, &proc_info.pid);
                                    if state.should_intercept(proc_info) {
                                        ConnectionAction::Intercept(proc_info.clone())
                                    } else {
                                        ConnectionAction::None
                                    }
                                } else {
                                    debug!("Unknown inbound packet. Passing through.");
                                    ConnectionAction::None
                                }
                            };
                            insert_into_connections(
                                packet.connection_id(),
                                &action,
                                &address.event(),
                                &mut connections,
                                &inject_handle,
                                &mut writer,
                            )
                            .await?;
                            process_packet(address, packet, &action, &inject_handle, &mut writer).await?;
                        }
                    }
                }
            }
            Event::SocketInfo(address) => {
                if address.process_id() == 4 {
                    debug!("Skipping PID 4");
                    continue;
                }

                let Ok(proto) = TransportProtocol::try_from(address.protocol()) else {
                    warn!("Unknown transport protocol: {}", address.protocol());
                    continue;
                };
                let connection_id = ConnectionId { proto, src: SocketAddr::from((address.local_address(), address.local_port())), dst: SocketAddr::from((address.remote_address(), address.remote_port())) };

                if connection_id.src.ip().is_multicast() || connection_id.dst.ip().is_multicast() {
                    continue;
                }

                match address.event() {
                    WinDivertEvent::SocketConnect | WinDivertEvent::SocketAccept => {
                        let make_entry = match connections.get(&connection_id) {
                            None => true,
                            Some(e) => matches!(e, ConnectionState::Unknown(_)),
                        };

                        debug!("{:<15?} make_entry={} pid={} {}", address.event(), make_entry, address.process_id(), connection_id);

                        if !make_entry { continue; }

                        let proc_info = {
                            let pid = address.process_id();
                            ProcessInfo { pid, process_name: get_process_name(pid).map(|x| x.to_string_lossy().into_owned()).ok() }
                        };

                        let action = if state.should_intercept(&proc_info) { ConnectionAction::Intercept(proc_info) } else { ConnectionAction::None };

                        insert_into_connections(connection_id, &action, &address.event(), &mut connections, &inject_handle, &mut writer).await?;
                    }
                    WinDivertEvent::SocketListen => {
                        let pid = address.process_id();
                        let process_name = get_process_name(pid).map(|x| x.to_string_lossy().into_owned()).ok();
                        debug!("Registering {:?} on {}.", process_name, connection_id.src);
                        active_listeners.insert(connection_id.src, proto, ProcessInfo { pid, process_name });
                    }
                    WinDivertEvent::SocketClose => {
                        if let Some(ConnectionState::Unknown(packets)) = connections.get_mut(&connection_id) { packets.clear(); }
                        active_listeners.remove(connection_id.src, proto);
                    }
                    _ => {}
                }
            }
            Event::Ipc(ipc::from_proxy::Message::Packet(ipc::Packet { data: buf })) => {
                let mut address = unsafe { WinDivertAddress::<NetworkLayer>::new() };
                address.set_outbound(true);
                address.set_ip_checksum(false);
                address.set_tcp_checksum(false);
                address.set_udp_checksum(false);

                let packet = match InternetPacket::try_from(buf.to_vec()) {
                    Ok(p) => p,
                    Err(e) => { info!("Error parsing packet: {:?}", e); continue; }
                };

                debug!("Injecting: {} {} with outbound={} loopback={}", packet.connection_id(), packet.tcp_flag_str(), address.outbound(), address.loopback());

                let packet = WinDivertPacket::<NetworkLayer> { address, data: packet.inner().into() };
                inject_handle.send(&packet)?;
            }
            Event::Ipc(ipc::from_proxy::Message::InterceptConf(conf)) => {
                state = conf.try_into()?;
                info!("{}", state.description());

                connections.clear();
                active_listeners.clear();
                for e in crate::windows::network::network_table()? {
                    let proc_info = ProcessInfo { pid: e.pid, process_name: get_process_name(e.pid).map(|x| x.to_string_lossy().into_owned()).ok() };
                    let proto = TransportProtocol::try_from(e.protocol)?;
                    if e.remote_addr.ip().is_unspecified() {
                        active_listeners.insert(e.local_addr, proto, proc_info);
                    } else {
                        let connection_id = ConnectionId { proto, src: e.local_addr, dst: e.remote_addr };
                        let action = if state.should_intercept(&proc_info) { ConnectionAction::Intercept(proc_info) } else { ConnectionAction::None };
                        insert_into_connections(connection_id, &action, &WinDivertEvent::ReflectOpen, &mut connections, &inject_handle, &mut writer).await?;
                    }
                }
            }
        }
    }
}

async fn handle_ipc<R>(
    mut ipc: R,
    tx: UnboundedSender<Event>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; crate::packet_sources::IPC_BUF_SIZE];
    loop {
        tokio::select! {
            r = ipc.read(&mut buf) => {
                match r {
                    Ok(len) if len > 0 => {
                        let mut cursor = Cursor::new(&buf[..len]);
                        let Ok(FromProxy { message: Some(message)}) = FromProxy::decode(&mut cursor) else {
                            return Err(anyhow!("Received invalid IPC message"));
                        };
                        tx.send(Event::Ipc(message))?;
                    }
                    _ => {
                        info!("IPC read failed. Exiting.");
                        std::process::exit(0);
                    }
                }
            }
        }
    }
}

fn relay_socket_events(handle: WinDivert<SocketLayer>, tx: tokio::sync::mpsc::UnboundedSender<Event>) {
    loop {
        let packets = handle.recv_ex(1);
        match packets {
            Ok(packets) => {
                for packet in packets {
                    if tx.send(Event::SocketInfo(packet.address)).is_err() {
                        return;
                    }
                }
            }
            Err(err) => {
                eprintln!("WinDivert Error: {err:?}");
                std::process::exit(74);
            }
        };
    }
}

fn relay_network_events(handle: WinDivert<NetworkLayer>, tx: tokio::sync::mpsc::UnboundedSender<Event>) {
    const MAX_PACKETS: usize = 1;
    let mut buf = [0u8; MAX_PACKET_SIZE * MAX_PACKETS];
    loop {
        let packets = handle.recv_ex(Some(&mut buf), MAX_PACKETS);
        match packets {
            Ok(packets) => {
                for packet in packets {
                    if tx.send(Event::NetworkPacket(packet.address, packet.data.into())).is_err() {
                        return;
                    }
                }
            }
            Err(err) => {
                eprintln!("WinDivert Error: {err:?}");
                std::process::exit(74);
            }
        };
    }
}

async fn insert_into_connections<W>(
    connection_id: ConnectionId,
    action: &ConnectionAction,
    event: &WinDivertEvent,
    connections: &mut LruCache<ConnectionId, ConnectionState>,
    inject_handle: &WinDivert<NetworkLayer>,
    writer: &mut W,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    debug!("Adding: {} with {:?} ({:?})", &connection_id, action, event);
    // no matter which action we do, the reverse direction is whitelisted.

    let existing1 = connections.insert(
        connection_id.reverse(),
        ConnectionState::Known(ConnectionAction::None),
    );
    let existing2 = connections.insert(connection_id, ConnectionState::Known(action.clone()));

    if let Some(ConnectionState::Unknown(packets)) = existing1 {
        for (a, p) in packets {
            process_packet(a, p, &ConnectionAction::None, inject_handle, writer).await?;
        }
    }
    if let Some(ConnectionState::Unknown(packets)) = existing2 {
        for (a, p) in packets {
            process_packet(a, p, action, inject_handle, writer).await?;
        }
    }
    Ok(())
}

async fn process_packet<W>(
    address: WinDivertAddress<NetworkLayer>,
    mut packet: InternetPacket,
    action: &ConnectionAction,
    inject_handle: &WinDivert<NetworkLayer>,
    writer: &mut W,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    match action {
        ConnectionAction::None => {
            debug!(
                "Forwarding: {} {} outbound={} loopback={}",
                packet.connection_id(),
                packet.tcp_flag_str(),
                address.outbound(),
                address.loopback()
            );
            inject_handle
                .send(&WinDivertPacket::<NetworkLayer> {
                    address,
                    data: packet.inner().into(),
                })
                .context("failed to re-inject packet")?;
        }
        ConnectionAction::Intercept(ProcessInfo { pid, process_name }) => {
            debug!(
                "Intercepting: {} {} outbound={} loopback={}",
                packet.connection_id(),
                packet.tcp_flag_str(),
                address.outbound(),
                address.loopback()
            );

             if !address.ip_checksum() {
                packet.recalculate_ip_checksum();
            }
            if !address.tcp_checksum() {
                packet.recalculate_tcp_checksum();
            }
            if !address.udp_checksum() {
                packet.recalculate_udp_checksum();
            }

            // Build PacketWithMeta and write to IPC writer so forward_packets will read it.
            let mut buf = Vec::with_capacity(crate::packet_sources::IPC_BUF_SIZE);
            let pm = ipc::PacketWithMeta {
                data: Bytes::from(<Vec<u8>>::from(packet.inner())),
                tunnel_info: Some(ipc::TunnelInfo {
                    pid: Some(*pid),
                    process_name: process_name.clone(),
                }),
            };
            pm.encode(&mut buf)?;
            // let t1 = std::time::Instant::now();
            writer.write_all(&buf).await?;
            // let t2 = std::time::Instant::now();
            // if (t2 - t1).as_millis() > 10 {
            //     log::warn!("writer.write_all() took {} ms", (t2 - t1).as_millis());
            // }
        }
    }
    Ok(())
}
