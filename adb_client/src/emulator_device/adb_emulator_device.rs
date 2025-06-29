use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::LazyLock,
};
use std::net::{IpAddr, SocketAddr};
use crate::{ADBServerDevice, Result, RustADBError, TCPEmulatorTransport};
use regex::Regex;

static EMULATOR_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^emulator-(?P<port>\\d+)$").expect("wrong syntax for emulator regex")
});

/// Represents an emulator connected to the ADB server.
#[derive(Debug)]
pub struct ADBEmulatorDevice {
    /// Unique device identifier.
    pub identifier: String,
    /// Internal [TCPEmulatorTransport]
    transport: TCPEmulatorTransport,
}

impl ADBEmulatorDevice {
    /// Instantiates a new [ADBEmulatorDevice]
    pub fn connect(identifier: String, ip_address: Option<IpAddr>) -> Result<Self> {
        let ip_address = match ip_address {
            Some(ip_address) => ip_address,
            None => Ipv4Addr::new(127, 0, 0, 1).into(),
        };

        let groups = EMULATOR_REGEX
            .captures(&identifier)
            .ok_or(RustADBError::DeviceNotFound(format!(
                "Device {} is likely not an emulator",
                identifier
            )))?;

        let port = groups
            .name("port")
            .ok_or(RustADBError::RegexParsingError)?
            .as_str()
            .parse::<u16>()?;

        let socket_addr = SocketAddr::new(ip_address, port);

        let transport = TCPEmulatorTransport::connect(socket_addr)?;
        Ok(Self {
            identifier,
            transport,
        })
    }

    pub(crate) fn get_transport_mut(&mut self) -> &mut TCPEmulatorTransport {
        &mut self.transport
    }
}

impl TryFrom<ADBServerDevice> for ADBEmulatorDevice {
    type Error = RustADBError;

    fn try_from(value: ADBServerDevice) -> std::result::Result<Self, Self::Error> {
        match &value.identifier {
            Some(device_identifier) => ADBEmulatorDevice::connect(
                device_identifier.clone(),
                Some(value.transport.get_socketaddr().ip()),
            ),
            None => Err(RustADBError::DeviceNotFound(
                "cannot connect to an emulator device without knowing its identifier".to_string(),
            )),
        }
    }
}

impl Drop for ADBEmulatorDevice {
    fn drop(&mut self) {
        // Best effort here
        let _ = self.transport.disconnect();
    }
}
