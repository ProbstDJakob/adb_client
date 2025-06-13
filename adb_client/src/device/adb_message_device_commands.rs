use crate::{ADBDeviceExt, ADBMessageTransport, RebootType, Result, models::AdbStatResponse};
use std::{
    io::{Read, Write},
    path::Path,
};

use super::ADBMessageDevice;

impl<T: ADBMessageTransport + Clone + Send + 'static> ADBDeviceExt for ADBMessageDevice<T> {
    fn shell_command(&mut self, command: &[&str], output: impl Write) -> Result<()> {
        self.shell_command(command, output)
    }

    fn shell(&mut self, reader: impl Read, writer: impl Write + Send + 'static) -> Result<()> {
        self.shell(reader, writer)
    }

    fn stat(&mut self, remote_path: &str) -> Result<AdbStatResponse> {
        self.stat(remote_path)
    }

    fn pull(&mut self, source: impl AsRef<str>, output: impl Write) -> Result<()> {
        self.pull(source, output)
    }

    fn push(&mut self, stream: impl Read, path: impl AsRef<str>) -> Result<()> {
        self.push(stream, path)
    }

    fn reboot(&mut self, reboot_type: RebootType) -> Result<()> {
        self.reboot(reboot_type)
    }

    fn install(&mut self, apk_path: impl AsRef<Path>) -> Result<()> {
        self.install(apk_path)
    }

    fn uninstall(&mut self, package: &str) -> Result<()> {
        self.uninstall(package)
    }

    fn framebuffer_inner(&mut self) -> Result<image::ImageBuffer<image::Rgba<u8>, Vec<u8>>> {
        self.framebuffer_inner()
    }
}
