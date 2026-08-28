//! RMCP stdio transport over an Astrid-owned process-wrap 10 child.

use std::future::Future;
use std::io;
use std::process::Stdio;
use std::time::Duration;

use process_wrap::tokio::{ChildWrapper, CommandWrap};
use rmcp::service::{RoleClient, RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::Transport;
use rmcp::transport::async_rw::AsyncRwTransport;
use tokio::process::{ChildStdin, ChildStdout};
use tracing::warn;

/// RMCP's child transport waits this long for a cooperative child after
/// closing protocol writes before forcing tree termination. Preserve the
/// upstream contract rather than inventing a second Astrid timeout.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) struct OwnedProcessTransport {
    child: Option<Box<dyn ChildWrapper>>,
    transport: AsyncRwTransport<RoleClient, ChildStdout, ChildStdin>,
}

impl OwnedProcessTransport {
    pub(crate) fn new(mut command: CommandWrap) -> io::Result<Self> {
        command
            .command_mut()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let child = command.spawn()?;
        let (child, stdout, stdin) = take_stdio(child)?;
        Ok(Self {
            child: Some(child),
            transport: AsyncRwTransport::new(stdout, stdin),
        })
    }

    async fn graceful_shutdown(&mut self) -> io::Result<()> {
        self.transport.close().await?;

        let Some(mut child) = self.child.take() else {
            return Ok(());
        };

        let Ok(result) = tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, child.wait()).await else {
            if let Err(error) = Box::into_pin(child.kill()).await {
                warn!(error = %error, "Error killing MCP child process tree");
                return Err(error);
            }
            return Ok(());
        };

        match result {
            Ok(status) => {
                tracing::info!(?status, "MCP child exited gracefully");
                Ok(())
            },
            Err(error) => {
                warn!(error = %error, "Error waiting for MCP child");
                Err(error)
            },
        }
    }
}

fn take_stdio(
    mut child: Box<dyn ChildWrapper>,
) -> io::Result<(Box<dyn ChildWrapper>, ChildStdout, ChildStdin)> {
    let stdin = child
        .stdin()
        .take()
        .ok_or_else(|| io::Error::other("MCP child stdin was unavailable or already taken"))?;
    let stdout = child
        .stdout()
        .take()
        .ok_or_else(|| io::Error::other("MCP child stdout was unavailable or already taken"))?;
    Ok((child, stdout, stdin))
}

impl Drop for OwnedProcessTransport {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            tokio::spawn(async move {
                if let Err(error) = Box::into_pin(child.kill()).await {
                    warn!(error = %error, "Error killing dropped MCP child process tree");
                }
            });
        }
    }
}

impl Transport<RoleClient> for OwnedProcessTransport {
    type Error = io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleClient>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        self.transport.send(item)
    }

    fn receive(&mut self) -> impl Future<Output = Option<RxJsonRpcMessage<RoleClient>>> + Send {
        self.transport.receive()
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.graceful_shutdown()
    }
}
