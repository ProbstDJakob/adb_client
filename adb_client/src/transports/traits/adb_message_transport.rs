use std::time::Duration;

use crate::{Result, device::ADBTransportMessage};

const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(u64::MAX);
const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// Trait representing a transport able to read and write messages.
pub trait ADBMessageTransport {
    /// Read a message using given timeout on the underlying transport
    fn read_message_with_timeout(&mut self, read_timeout: Duration) -> Result<ADBTransportMessage>;

    /// Read data to underlying connection, using default timeout
    fn read_message(&mut self) -> Result<ADBTransportMessage> {
        self.read_message_with_timeout(DEFAULT_READ_TIMEOUT)
    }

    /// Write a message using given timeout on the underlying transport
    fn write_message_with_timeout(
        &mut self,
        message: ADBTransportMessage,
        write_timeout: Duration,
    ) -> Result<()>;

    /// Write data to underlying connection, using default timeout
    fn write_message(&mut self, message: ADBTransportMessage) -> Result<()> {
        self.write_message_with_timeout(message, DEFAULT_WRITE_TIMEOUT)
    }
}

impl<T: ADBMessageTransport> ADBMessageTransport for &mut T {
    fn read_message_with_timeout(&mut self, read_timeout: Duration) -> Result<ADBTransportMessage> {
        (*self).read_message_with_timeout(read_timeout)
    }

    fn read_message(&mut self) -> Result<ADBTransportMessage> {
        (*self).read_message()
    }

    fn write_message_with_timeout(&mut self, message: ADBTransportMessage, write_timeout: Duration) -> Result<()> {
        (*self).write_message_with_timeout(message, write_timeout)
    }

    fn write_message(&mut self, message: ADBTransportMessage) -> Result<()> {
        (*self).write_message(message)
    }
}
