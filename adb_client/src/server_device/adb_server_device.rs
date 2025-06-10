use crate::{Result, TCPServerTransport, models::AdbServerCommand};
use std::net::{SocketAddr, SocketAddrV4};

/// Represents a device connected to the ADB server.
#[derive(Debug)]
pub struct ADBServerDevice {
    /// Unique device identifier.
    pub identifier: Option<String>,
    /// Internal [TCPServerTransport]
    pub(crate) transport: TCPServerTransport,
}

impl ADBServerDevice {
    /// Instantiates a new [ADBServerDevice], knowing its ADB identifier (as returned by `adb devices` command).
    pub fn connect(identifier: String, server_addr: Option<SocketAddr>) -> Result<Self> {
        let transport = server_addr.map_or_else(TCPServerTransport::connect_default, TCPServerTransport::connect)?;

        Ok(Self {
            identifier: Some(identifier),
            transport,
        })
    }

    /// Instantiates a new [ADBServerDevice], assuming only one is currently connected.
    pub fn connect_autodetect(server_addr: Option<SocketAddr>) -> Result<Self> {
        let transport = server_addr.map_or_else(TCPServerTransport::connect_default, TCPServerTransport::connect)?;

        Ok(Self {
            identifier: None,
            transport,
        })
    }

    /// Set device connection to use serial transport
    pub(crate) fn set_serial_transport(&mut self) -> Result<()> {
        let identifier = self.identifier.clone();
        if let Some(serial) = identifier {
            self.transport.send_adb_request(AdbServerCommand::TransportSerial(serial))?;
        } else {
            self.transport.send_adb_request(AdbServerCommand::TransportAny)?;
        }

        Ok(())
    }
}

impl Drop for ADBServerDevice {
    fn drop(&mut self) {
        // Best effort here
        let _ = self.transport.disconnect();
    }
}
