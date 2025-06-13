use super::ADBTransportMessage;
use super::adb_message_device::ADBMessageDevice;
use super::models::MessageCommand;
use crate::{ADBDeviceExt, ADBMessageTransport, Connection, Result, TcpTransport};
use rustls_pki_types::ServerName;
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::{io::Read, net::SocketAddr};

/// Represent a device reached and available over USB.
#[derive(Debug)]
pub struct ADBTcpDevice<C: Connection + Send + 'static> {
    inner: ADBMessageDevice<TcpTransport<C>>,
}

impl ADBTcpDevice<TcpStream> {
    /// Instantiate a new [`ADBTcpDevice`]
    pub fn new(address: SocketAddr) -> Result<Self> {
        Self::new_from_tcp_transport(TcpTransport::connect(address)?)
    }
}

impl<C: Connection + Send + 'static> ADBTcpDevice<C> {
    /// Instantiate a new [`ADBTcpDevice`]
    pub fn new_from_connection(server_name: ServerName, connection: C) -> Result<Self> {
        Self::new_from_tcp_transport(TcpTransport::new(server_name, connection)?)
    }

    fn new_from_tcp_transport(tcp_transport: TcpTransport<C>) -> Result<Self> {
        let mut device = Self {
            inner: ADBMessageDevice::new(tcp_transport),
        };

        device.connect()?;

        Ok(device)
    }

    /// Send initial connect
    fn connect(&mut self) -> Result<()> {
        let message = ADBTransportMessage::new(
            MessageCommand::Cnxn,
            0x01000000,
            1048576,
            format!("host::{}\0", env!("CARGO_PKG_NAME")).as_bytes(),
        );

        self.get_transport_mut().write_message(message)?;

        let message = self.get_transport_mut().read_message()?;

        // Check if client is requesting a secure connection and upgrade it if necessary
        match message.header().command() {
            MessageCommand::Stls => {
                self.get_transport_mut()
                    .write_message(ADBTransportMessage::new(MessageCommand::Stls, 1, 0, &[]))?;
                self.get_transport_mut().upgrade_connection()?;
                log::debug!("Connection successfully upgraded from TCP to TLS");
            }
            MessageCommand::Cnxn => {
                log::debug!("Unencrypted connection established");
            }
            _ => {
                return Err(crate::RustADBError::WrongResponseReceived(
                    "Expected CNXN or STLS command".to_string(),
                    message.header().command().to_string(),
                ));
            }
        }

        Ok(())
    }

    #[inline]
    fn get_transport_mut(&mut self) -> &mut TcpTransport<C> {
        self.inner.get_transport()
    }
}

impl<C: Connection + Send + 'static> ADBDeviceExt for ADBTcpDevice<C> {
    #[inline]
    fn shell_command(&mut self, command: &[&str], output: impl Write) -> Result<()> {
        self.inner.shell_command(command, output)
    }

    #[inline]
    fn shell(&mut self, reader: impl Read, writer: impl Write + Send + 'static) -> Result<()> {
        self.inner.shell(reader, writer)
    }

    #[inline]
    fn stat(&mut self, remote_path: &str) -> Result<crate::AdbStatResponse> {
        self.inner.stat(remote_path)
    }

    #[inline]
    fn pull(&mut self, source: impl AsRef<str>, output: impl Write) -> Result<()> {
        self.inner.pull(source, output)
    }

    #[inline]
    fn push(&mut self, stream: impl Read, path: impl AsRef<str>) -> Result<()> {
        self.inner.push(stream, path)
    }

    #[inline]
    fn reboot(&mut self, reboot_type: crate::RebootType) -> Result<()> {
        self.inner.reboot(reboot_type)
    }

    #[inline]
    fn install(&mut self, apk_path: impl AsRef<Path>) -> Result<()> {
        self.inner.install(apk_path)
    }

    #[inline]
    fn uninstall(&mut self, package: &str) -> Result<()> {
        self.inner.uninstall(package)
    }

    #[inline]
    fn framebuffer_inner(&mut self) -> Result<image::ImageBuffer<image::Rgba<u8>, Vec<u8>>> {
        self.inner.framebuffer_inner()
    }
}

impl<C: Connection + Send + 'static> Drop for ADBTcpDevice<C> {
    fn drop(&mut self) {
        // Best effort here
        let _ = self.get_transport_mut().disconnect();
    }
}
