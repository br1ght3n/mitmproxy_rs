use std::iter;
use std::path::PathBuf;

use anyhow::Result;
use tokio::io::duplex;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::intercept_conf::InterceptConf;
use crate::messages::{TransportCommand, TransportEvent};
use crate::packet_sources::{forward_packets, PacketSourceConf, PacketSourceTask, IPC_BUF_SIZE};
use crate::shutdown;

pub struct WindowsConf {
    // optional resource directory containing WinDivert files; mitmproxy-windows package ships
    // the DLL/SYS files and we will read them from there when needed.
    pub resource_dir: Option<PathBuf>,
}

impl PacketSourceConf for WindowsConf {
    type Task = WindowsTask;
    type Data = UnboundedSender<InterceptConf>;

    fn name(&self) -> &'static str {
        "Windows proxy"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: shutdown::Receiver,
    ) -> Result<(Self::Task, Self::Data)> {
        // Instead of launching an external redirector process, we'll run the redirector
        // logic in-process. Create a duplex stream and hand one side to forward_packets
        // and the other side to the inproc redirector task.
        let (conf_tx, conf_rx) = unbounded_channel();

        // Duplex buffer size: IPC_BUF_SIZE
        let (mut ipc_server, mut ipc_client) = duplex(IPC_BUF_SIZE);

        // spawn the in-process redirector using side `b` as its IPC channel
        let resource_dir = self.resource_dir.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::packet_sources::redirector_inproc::run_inproc(ipc_client, resource_dir).await {
                log::error!("redirector inproc failed: {}", e);
            }
        });

        Ok((
            WindowsTask {
                ipc_server,
                transport_events_tx,
                transport_commands_rx,
                conf_rx,
                shutdown,
            },
            conf_tx,
        ))
    }
}

pub struct WindowsTask {
    ipc_server: tokio::io::DuplexStream,
    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    conf_rx: UnboundedReceiver<InterceptConf>,
    shutdown: shutdown::Receiver,
}

impl PacketSourceTask for WindowsTask {
    async fn run(self) -> Result<()> {
        log::debug!("Using in-process redirector IPC stream");

        forward_packets(
            self.ipc_server,
            self.transport_events_tx,
            self.transport_commands_rx,
            self.conf_rx,
            self.shutdown,
        )
        .await
    }
}
