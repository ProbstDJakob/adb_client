use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256};
use rustls::{
    ClientConfig, ClientConnection, KeyLogFile, SignatureScheme, StreamOwned,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject},
};

use super::ADBMessageTransport;
use crate::{
    Result, RustADBError,
    device::{
        ADBTransportMessage, ADBTransportMessageHeader, MessageCommand, get_default_adb_key_path,
    },
};
use rustls_pki_types::ServerName;
use std::fmt::Debug;
use std::sync::MutexGuard;
use std::{
    fs::read_to_string,
    io::{Read, Write},
    mem,
    net::{Shutdown, SocketAddr, TcpStream},
    ops::{Deref, DerefMut},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Connection
pub trait Connection: Read + Write {
    /// Set read timeout
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()>;
    /// Set write timeout
    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()>;

    /// Disconnect
    fn disconnect(self) -> std::io::Result<()>;
}

impl Connection for TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }

    fn disconnect(self) -> std::io::Result<()> {
        self.shutdown(Shutdown::Both)
    }
}

impl<T: Connection> Connection for StreamOwned<ClientConnection, T> {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.sock.set_write_timeout(timeout)
    }

    fn disconnect(self) -> std::io::Result<()> {
        self.sock.disconnect()
    }
}

#[derive(Debug)]
enum CurrentConnection<C: Connection> {
    Tcp(C),
    Tls(StreamOwned<ClientConnection, C>),
}

impl<C: Connection> CurrentConnection<C> {
    fn set_read_timeout(&mut self, read_timeout: Duration) -> Result<()> {
        match self {
            CurrentConnection::Tcp(tcp_stream) => {
                Ok(tcp_stream.set_read_timeout(Some(read_timeout))?)
            }
            CurrentConnection::Tls(stream_owned) => {
                Ok(stream_owned.sock.set_read_timeout(Some(read_timeout))?)
            }
        }
    }

    fn set_write_timeout(&mut self, write_timeout: Duration) -> Result<()> {
        match self {
            CurrentConnection::Tcp(tcp_stream) => {
                Ok(tcp_stream.set_write_timeout(Some(write_timeout))?)
            }
            CurrentConnection::Tls(stream_owned) => {
                Ok(stream_owned.sock.set_write_timeout(Some(write_timeout))?)
            }
        }
    }

    fn disconnect(self) -> Result<()> {
        match self {
            CurrentConnection::Tcp(tcp_stream) => Ok(tcp_stream.disconnect()?),
            CurrentConnection::Tls(mut stream_owned) => {
                stream_owned.conn.send_close_notify();
                Ok(stream_owned.disconnect()?)
            }
        }
    }
}

impl<C: Connection> Read for CurrentConnection<C> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            CurrentConnection::Tcp(tcp_stream) => tcp_stream.read(buf),
            CurrentConnection::Tls(tls_conn) => tls_conn.read(buf),
        }
    }
}

impl<C: Connection> Write for CurrentConnection<C> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            CurrentConnection::Tcp(tcp_stream) => tcp_stream.write(buf),
            CurrentConnection::Tls(tls_conn) => tls_conn.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            CurrentConnection::Tcp(tcp_stream) => tcp_stream.flush(),
            CurrentConnection::Tls(tls_conn) => tls_conn.flush(),
        }
    }
}

#[derive(Debug)]
enum ConnectionState<C: Connection> {
    Connected(CurrentConnection<C>),
    Upgrading,
    Disconnected,
}

impl<C: Connection> ConnectionState<C> {
    fn get_connection(&mut self) -> Option<&mut CurrentConnection<C>> {
        match self {
            ConnectionState::Connected(current_connection) => Some(current_connection),
            ConnectionState::Upgrading => panic!("Upgrading the connection has paniced"),
            ConnectionState::Disconnected => None,
        }
    }

    fn get_connection_or_error(&mut self) -> Result<&mut CurrentConnection<C>> {
        self.get_connection()
            .ok_or(RustADBError::IOError(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "not connected",
            )))
    }
}

/// Transport running on Tcp
#[derive(Debug)]
pub struct TcpTransport<C: Connection> {
    server_name: ServerName<'static>,
    current_connection: Arc<Mutex<ConnectionState<C>>>,
    private_key_path: PathBuf,
}

impl<C: Connection> Clone for TcpTransport<C> {
    fn clone(&self) -> Self {
        Self {
            server_name: self.server_name.clone(),
            current_connection: self.current_connection.clone(),
            private_key_path: self.private_key_path.clone(),
        }
    }
}

fn certificate_from_pk(key_pair: &KeyPair) -> Result<Vec<CertificateDer<'static>>> {
    let certificate_params = CertificateParams::default();
    let certificate = certificate_params.self_signed(key_pair)?;
    Ok(vec![certificate.der().to_owned()])
}

impl TcpTransport<TcpStream> {
    /// Instantiate a new [`TcpTransport`]
    pub fn connect(address: SocketAddr) -> Result<Self> {
        Self::connect_with_custom_private_key(address, get_default_adb_key_path()?)
    }

    /// Instantiate a new [`TcpTransport`] using a given private key
    pub fn connect_with_custom_private_key(
        address: SocketAddr,
        private_key_path: PathBuf,
    ) -> Result<Self> {
        Ok(Self::new_with_custom_private_key(
            address.ip().into(),
            TcpStream::connect(address)?,
            private_key_path,
        ))
    }
}

impl<C: Connection> TcpTransport<C> {
    /// Instantiate a new [`TcpTransport`]
    pub fn new(server_name: ServerName<'_>, connection: C) -> Result<Self> {
        Ok(Self::new_with_custom_private_key(
            server_name,
            connection,
            get_default_adb_key_path()?,
        ))
    }

    /// Instantiate a new [`TcpTransport`] using a given private key
    pub fn new_with_custom_private_key(
        server_name: ServerName,
        connection: C,
        private_key_path: PathBuf,
    ) -> Self {
        Self {
            server_name: server_name.to_owned(),
            current_connection: Arc::new(Mutex::new(ConnectionState::Connected(
                CurrentConnection::Tcp(connection),
            ))),
            private_key_path,
        }
    }

    pub(crate) fn upgrade_connection(&mut self) -> Result<()>
    where
        Self: ADBMessageTransport,
    {
        {
            let mut current_connection = self.current_connection.lock()?;
            match current_connection.get_connection() {
                Some(CurrentConnection::Tcp(_)) => {
                    // TODO: Check if we cannot be more precise

                    let pk_content = read_to_string(&self.private_key_path)?;

                    let key_pair =
                        KeyPair::from_pkcs8_pem_and_sign_algo(&pk_content, &PKCS_RSA_SHA256)?;

                    let certificate = certificate_from_pk(&key_pair)?;
                    let private_key = PrivatePkcs8KeyDer::from_pem_file(&self.private_key_path)?;

                    let mut client_config = ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
                        .with_client_auth_cert(certificate, private_key.into())?;

                    client_config.key_log = Arc::new(KeyLogFile::new());

                    let rc_config = Arc::new(client_config);
                    let conn = ClientConnection::new(rc_config, self.server_name.clone())?;

                    // Update current connection state to now use TLS protocol
                    // WARNING: The following code should not use the ? operator, as this
                    //          would leave `current_connection` with `None`!
                    let ConnectionState::Connected(CurrentConnection::Tcp(tcp_stream)) =
                        mem::replace(&mut *current_connection, ConnectionState::Upgrading)
                    else {
                        unreachable!()
                    };
                    *current_connection = ConnectionState::Connected(CurrentConnection::Tls(
                        StreamOwned::new(conn, tcp_stream),
                    ));
                }

                Some(CurrentConnection::Tls(_)) => {
                    return Err(RustADBError::UpgradeError(
                        "cannot upgrade a TLS connection...".into(),
                    ));
                }
                None => {
                    return Err(RustADBError::UpgradeError(
                        "cannot upgrade a non-existing connection...".into(),
                    ));
                }
            }
        }

        let message = self.read_message()?;
        match message.header().command() {
            MessageCommand::Cnxn => {
                let device_infos = String::from_utf8(message.into_payload())?;
                log::debug!("received device info: {device_infos}");
                Ok(())
            }
            c => Err(RustADBError::ADBRequestFailed(format!(
                "Wrong command received {}",
                c
            ))),
        }
    }

    pub(crate) fn disconnect(&self) -> Result<()> {
        log::debug!("disconnecting...");
        if let ConnectionState::Connected(current_connection) = mem::replace(
            &mut *self.current_connection.lock()?,
            ConnectionState::Disconnected,
        ) {
            current_connection.disconnect()?;
        }

        Ok(())
    }
}

impl<C: Connection + Send + 'static> ADBMessageTransport for TcpTransport<C> {
    fn read_message_with_timeout(
        &mut self,
        read_timeout: std::time::Duration,
    ) -> Result<crate::device::ADBTransportMessage> {
        let mut lock = self.current_connection.lock()?;
        let raw_connection = lock.get_connection_or_error()?;

        raw_connection.set_read_timeout(read_timeout)?;

        let mut data = [0; 24];
        let mut total_read = 0;
        loop {
            total_read += raw_connection.read(&mut data[total_read..])?;
            if total_read == data.len() {
                break;
            }
        }

        let header = ADBTransportMessageHeader::try_from(data)?;

        if header.data_length() != 0 {
            let mut msg_data = vec![0_u8; header.data_length() as usize];
            let mut total_read = 0;
            loop {
                total_read += raw_connection.read(&mut msg_data[total_read..])?;
                if total_read == msg_data.capacity() {
                    break;
                }
            }

            let message = ADBTransportMessage::from_header_and_payload(header, msg_data);

            // Check message integrity
            if !message.check_message_integrity() {
                return Err(RustADBError::InvalidIntegrity(
                    ADBTransportMessageHeader::compute_crc32(message.payload()),
                    message.header().data_crc32(),
                ));
            }

            return Ok(message);
        }

        Ok(ADBTransportMessage::from_header_and_payload(header, vec![]))
    }

    fn write_message_with_timeout(
        &mut self,
        message: ADBTransportMessage,
        write_timeout: Duration,
    ) -> Result<()> {
        let message_bytes = message.header().as_bytes()?;
        let mut lock = self.current_connection.lock()?;
        let raw_connection = lock.get_connection_or_error()?;

        raw_connection.set_write_timeout(write_timeout)?;

        let mut total_written = 0;
        loop {
            total_written += raw_connection.write(&message_bytes[total_written..])?;
            if total_written == message_bytes.len() {
                raw_connection.flush()?;
                break;
            }
        }

        let payload = message.into_payload();
        if !payload.is_empty() {
            let mut total_written = 0;
            loop {
                total_written += raw_connection.write(&payload[total_written..])?;
                if total_written == payload.len() {
                    raw_connection.flush()?;
                    break;
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}
