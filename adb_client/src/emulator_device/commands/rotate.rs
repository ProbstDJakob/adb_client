use crate::{ADBEmulatorDevice, Result, emulator_device::ADBEmulatorCommand};

impl ADBEmulatorDevice {
    /// Send a SMS to this emulator with given content with given phone number
    pub fn rotate(&mut self) -> Result<()> {
        self.get_transport_mut().send_command(ADBEmulatorCommand::Rotate)
    }
}
