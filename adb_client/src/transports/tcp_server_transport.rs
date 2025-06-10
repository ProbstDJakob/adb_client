use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::str::FromStr;

use byteorder::{ByteOrder, LittleEndian};

use crate::models::AdbServerCommand;
use crate::models::{AdbRequestStatus, SyncCommand};
use crate::{Result, RustADBError};

const DEFAULT_SERVER_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const DEFAULT_SERVER_PORT: u16 = 5037;

/// Server transport running on top on TCP
#[derive(Debug)]
pub struct TCPServerTransport {
    socket_addr: SocketAddr,
    tcp_stream: TcpStream,
}

impl TCPServerTransport {
    /// Instantiates a new instance of [TCPServerTransport]
    pub fn connect(socket_addr: SocketAddr) -> Result<Self> {
        let tcp_stream = TcpStream::connect(socket_addr)?;
        tcp_stream.set_nodelay(true)?;
        log::trace!("Successfully connected to {}", socket_addr);

        Ok(Self {
            socket_addr,
            tcp_stream,
        })
    }

    /// Instantiates a new instance of [TCPServerTransport] and connecting to the default address and port
    pub fn connect_default() -> Result<Self> {
        Self::connect(SocketAddrV4::new(DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT).into())
    }

    /// Get underlying [SocketAddr]
    pub fn get_socketaddr(&self) -> SocketAddr {
        self.socket_addr
    }

    pub(crate) fn proxy_connection(
        &mut self,
        adb_command: AdbServerCommand,
        with_response: bool,
    ) -> Result<Vec<u8>> {
        self.send_adb_request(adb_command)?;

        if with_response {
            let length = self.get_hex_body_length()?;
            let mut body = vec![
                0;
                length
                    .try_into()
                    .map_err(|_| RustADBError::ConversionError)?
            ];
            if length > 0 {
                self.get_raw_connection().read_exact(&mut body)?;
            }

            Ok(body)
        } else {
            Ok(vec![])
        }
    }

    pub(crate) fn get_raw_connection(&self) -> &TcpStream {
        &self.tcp_stream
    }

    /// Gets the body length from hexadecimal value
    pub(crate) fn get_hex_body_length(&mut self) -> Result<u32> {
        let length_buffer = self.read_body_length()?;
        Ok(u32::from_str_radix(
            std::str::from_utf8(&length_buffer)?,
            16,
        )?)
    }

    /// Send the given [SyncCommand] to ADB server, and checks that the request has been taken in consideration.
    pub(crate) fn send_sync_request(&mut self, command: SyncCommand) -> Result<()> {
        // First 4 bytes are the name of the command we want to send
        // (e.g. "SEND", "RECV", "STAT", "LIST")
        Ok(self.get_raw_connection().write_all(command.to_string().as_bytes())?)
    }

    /// Gets the body length from a LittleEndian value
    pub(crate) fn get_body_length(&mut self) -> Result<u32> {
        let length_buffer = self.read_body_length()?;
        Ok(LittleEndian::read_u32(&length_buffer))
    }

    /// Read 4 bytes representing body length
    fn read_body_length(&mut self) -> Result<[u8; 4]> {
        let mut length_buffer = [0; 4];
        self.get_raw_connection().read_exact(&mut length_buffer)?;

        Ok(length_buffer)
    }

    /// Send the given [AdbCommand] to ADB server, and checks that the request has been taken in consideration.
    /// If an error occurred, a [RustADBError] is returned with the response error string.
    pub(crate) fn send_adb_request(&mut self, command: AdbServerCommand) -> Result<()> {
        let adb_command_string = command.to_string();
        let adb_request = format!("{:04x}{}", adb_command_string.len(), adb_command_string);

        self.get_raw_connection().write_all(adb_request.as_bytes())?;

        self.read_adb_response()
    }

    /// Read a response from ADB server
    pub(crate) fn read_adb_response(&mut self) -> Result<()> {
        // Reads returned status code from ADB server
        let mut request_status = [0; 4];
        self.get_raw_connection().read_exact(&mut request_status)?;

        match AdbRequestStatus::from_str(std::str::from_utf8(request_status.as_ref())?)? {
            AdbRequestStatus::Fail => {
                // We can keep reading to get further details
                let length = self.get_hex_body_length()?;

                let mut body = vec![
                    0;
                    length
                        .try_into()
                        .map_err(|_| RustADBError::ConversionError)?
                ];
                if length > 0 {
                    self.get_raw_connection().read_exact(&mut body)?;
                }

                Err(RustADBError::ADBRequestFailed(String::from_utf8(body)?))
            }
            AdbRequestStatus::Okay => Ok(()),
        }
    }

    pub(crate) fn disconnect(&mut self) -> Result<()> {
        self.get_raw_connection().shutdown(std::net::Shutdown::Both)?;
        log::trace!("Disconnected from {}", self.get_raw_connection().peer_addr()?);

        Ok(())
    }
}
