use homedir::my_home;
use std::fs::read_to_string;
use std::{
    io::{BufRead, BufReader, Error, ErrorKind, Read, Write},
    net::{SocketAddrV4, TcpStream},
};
use std::net::SocketAddr;
use crate::{Result, RustADBError, emulator_device::ADBEmulatorCommand};

/// Emulator transport running on top on TCP.
#[derive(Debug)]
pub struct TCPEmulatorTransport {
    socket_addr: SocketAddr,
    tcp_stream: BufReader<TcpStream>,
}

impl TCPEmulatorTransport {
    /// Instantiates a new instance of [TCPEmulatorTransport]
    pub fn connect(socket_addr: SocketAddr) -> Result<Self> {
        let mut tcp_stream = BufReader::new(TcpStream::connect(socket_addr)?);

        log::trace!("Successfully connected to {}", socket_addr);

        // Android Console: Authentication required
        // Android Console: type 'auth <auth_token>' to authenticate
        // Android Console: you can find your <auth_token> in
        // '/home/xxx/.emulator_console_auth_token'
        for _ in 0..=4 {
            tcp_stream.skip_until(b'\n')?;
        }

        log::trace!("Authentication successful");

        let mut this = Self {
            socket_addr,
            tcp_stream,
        };

        this.authenticate()?;

        Ok(this)
    }

    fn authenticate(&mut self) -> Result<()> {
        let home = match my_home()? {
            Some(home) => home,
            None => return Err(RustADBError::NoHomeDirectory),
        };

        let token = read_to_string(home.join(".emulator_console_auth_token"))?;

        Ok(self.send_command(ADBEmulatorCommand::Authenticate(token))?)
    }

    /// Send an [ADBEmulatorCommand] to this emulator
    pub(crate) fn send_command(&mut self, command: ADBEmulatorCommand) -> Result<()> {
        // Send command
        self.tcp_stream.get_mut().write_all(command.to_string().as_bytes())?;

        // Check is an error occurred skipping lines depending on command
        self.check_error(command.skip_response_lines())?;

        Ok(())
    }

    fn check_error(&mut self, skipping: u8) -> Result<()> {
        for _ in 0..skipping {
            let mut line = String::new();
            self.tcp_stream.read_line(&mut line)?;
            if line.starts_with("KO:") {
                return Err(RustADBError::ADBRequestFailed(line));
            }
        }

        let mut line = String::new();
        self.tcp_stream.read_line(&mut line)?;

        match line.starts_with("OK") {
            true => Ok(()),
            false => Err(RustADBError::ADBRequestFailed(line)),
        }
    }

    pub(crate) fn disconnect(&mut self) -> Result<()> {
        self.tcp_stream
            .get_ref()
            .shutdown(std::net::Shutdown::Both)?;
        log::trace!(
            "Disconnected from {}",
            self.tcp_stream.get_ref().peer_addr()?
        );

        Ok(())
    }
}
