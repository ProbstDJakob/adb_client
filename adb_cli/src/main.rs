#![doc = include_str!("../README.md")]

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod adb_termios;

mod handlers;
mod models;
mod utils;

use adb_client::{ADBDeviceExt, ADBServer, ADBServerDevice, ADBTcpDevice, ADBUSBDevice, AdbStatResponse, Connection, Framebuffer, MDNSDiscoveryService, RebootType};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use adb_termios::ADBTermios;

use anyhow::Result;
use clap::Parser;
use handlers::{handle_emulator_commands, handle_host_commands, handle_local_commands};
use models::{DeviceCommands, LocalCommand, MainCommand, Opts};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use utils::setup_logger;

enum Device<T: Connection + Send + 'static> {
    Local(ADBServerDevice),
    Usb(ADBUSBDevice),
    Tcp(ADBTcpDevice<T>),
}

impl<T: Connection + Send + 'static> ADBDeviceExt for Device<T> {
    fn shell_command(&mut self, command: &[&str], output: impl Write) -> adb_client::Result<()> {
        match self {
            Device::Local(device) => device.shell_command(command, output),
            Device::Usb(device) => device.shell_command(command, output),
            Device::Tcp(device) => device.shell_command(command, output),
        }
    }

    fn shell(&mut self, reader: impl Read, writer: impl Write + Send + 'static) -> adb_client::Result<()> {
        match self {
            Device::Local(device) => device.shell(reader, writer),
            Device::Usb(device) => device.shell(reader, writer),
            Device::Tcp(device) => device.shell(reader, writer),
        }
    }

    fn stat(&mut self, remote_path: &str) -> adb_client::Result<AdbStatResponse> {
        match self {
            Device::Local(device) => device.stat(remote_path),
            Device::Usb(device) => device.stat(remote_path),
            Device::Tcp(device) => device.stat(remote_path),
        }
    }

    fn pull(&mut self, source: impl AsRef<str>, output: impl Write) -> adb_client::Result<()> {
        match self {
            Device::Local(device) => device.pull(source, output),
            Device::Usb(device) => device.pull(source, output),
            Device::Tcp(device) => device.pull(source, output),
        }
    }

    fn push(&mut self, stream: impl Read, path: impl AsRef<str>) -> adb_client::Result<()> {
        match self {
            Device::Local(device) => device.push(stream, path),
            Device::Usb(device) => device.push(stream, path),
            Device::Tcp(device) => device.push(stream, path),
        }
    }

    fn reboot(&mut self, reboot_type: RebootType) -> adb_client::Result<()> {
        match self {
            Device::Local(device) => device.reboot(reboot_type),
            Device::Usb(device) => device.reboot(reboot_type),
            Device::Tcp(device) => device.reboot(reboot_type),
        }
    }

    fn run_activity(&mut self, package: &str, activity: &str) -> adb_client::Result<Vec<u8>> {
        match self {
            Device::Local(device) => device.run_activity(package, activity),
            Device::Usb(device) => device.run_activity(package, activity),
            Device::Tcp(device) => device.run_activity(package, activity),
        }
    }

    fn install(&mut self, apk_path: impl AsRef<Path>) -> adb_client::Result<()> {
        match self {
            Device::Local(device) => device.install(apk_path),
            Device::Usb(device) => device.install(apk_path),
            Device::Tcp(device) => device.install(apk_path),
        }
    }

    fn uninstall(&mut self, package: &str) -> adb_client::Result<()> {
        match self {
            Device::Local(device) => device.uninstall(package),
            Device::Usb(device) => device.uninstall(package),
            Device::Tcp(device) => device.uninstall(package),
        }
    }

    fn framebuffer_inner(&mut self) -> adb_client::Result<Framebuffer> {
        match self {
            Device::Local(device) => device.framebuffer_inner(),
            Device::Usb(device) => device.framebuffer_inner(),
            Device::Tcp(device) => device.framebuffer_inner(),
        }
    }

    fn framebuffer(&mut self, path: impl AsRef<Path>) -> adb_client::Result<()> {
        match self {
            Device::Local(device) => device.framebuffer(path),
            Device::Usb(device) => device.framebuffer(path),
            Device::Tcp(device) => device.framebuffer(path),
        }
    }

    fn framebuffer_bytes(&mut self) -> adb_client::Result<Vec<u8>> {
        match self {
            Device::Local(device) => device.framebuffer_bytes(),
            Device::Usb(device) => device.framebuffer_bytes(),
            Device::Tcp(device) => device.framebuffer_bytes(),
        }
    }
}

fn main() -> Result<()> {
    // This depends on `clap`
    let opts = Opts::parse();

    // SAFETY:
    // We are assuming the entire process is single-threaded
    // at this point.
    // This seems true for the current version of `clap`,
    // but there's no guarantee for future updates
    unsafe { setup_logger(opts.debug) };

    // Directly handling methods / commands that aren't linked to [`ADBDeviceExt`] trait.
    // Other methods just have to create a concrete [`ADBDeviceExt`] instance, and return it.
    // This instance will then be used to execute desired command.
    let (mut device, commands) = match opts.command {
        MainCommand::Host(server_command) => return Ok(handle_host_commands(server_command)?),
        MainCommand::Emu(emulator_command) => return handle_emulator_commands(emulator_command),
        MainCommand::Local(server_command) => {
            // Must start server to communicate with device, but only if this is a local one.
            let server_address_ip = server_command.address.ip();
            if server_address_ip.is_loopback() || server_address_ip.is_unspecified() {
                ADBServer::start(&HashMap::default(), &None);
            }

            let device = match server_command.serial {
                Some(serial) => ADBServerDevice::connect(serial, Some(server_command.address))?,
                None => ADBServerDevice::connect_autodetect(Some(server_command.address))?,
            };

            match server_command.command {
                LocalCommand::DeviceCommands(device_commands) => (Device::Local(device), device_commands),
                LocalCommand::LocalDeviceCommand(local_device_command) => {
                    return handle_local_commands(device, local_device_command);
                }
            }
        }
        MainCommand::Usb(usb_command) => {
            let device = match (usb_command.vendor_id, usb_command.product_id) {
                (Some(vid), Some(pid)) => match usb_command.path_to_private_key {
                    Some(pk) => ADBUSBDevice::new_with_custom_private_key(vid, pid, pk)?,
                    None => ADBUSBDevice::new(vid, pid)?,
                },
                (None, None) => match usb_command.path_to_private_key {
                    Some(pk) => ADBUSBDevice::autodetect_with_custom_private_key(pk)?,
                    None => ADBUSBDevice::autodetect()?,
                },
                _ => {
                    anyhow::bail!(
                        "please either supply values for both the --vendor-id and --product-id flags or none."
                    );
                }
            };
            (Device::Usb(device), usb_command.commands)
        }
        MainCommand::Tcp(tcp_command) => {
            let device = ADBTcpDevice::new(tcp_command.address)?;
            (Device::Tcp(device), tcp_command.commands)
        }
        MainCommand::Mdns => {
            let mut service = MDNSDiscoveryService::new()?;

            let (tx, rx) = std::sync::mpsc::channel();
            service.start(tx)?;

            log::info!("Starting mdns discovery...");
            while let Ok(device) = rx.recv() {
                log::info!(
                    "Found device {} with addresses {:?}",
                    device.fullname,
                    device.addresses
                )
            }

            return Ok(service.shutdown()?);
        }
    };

    match commands {
        DeviceCommands::Shell { commands } => {
            if commands.is_empty() {
                // Need to duplicate some code here as ADBTermios [Drop] implementation resets terminal state.
                // Using a scope here would call drop() too early..
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    let mut adb_termios = ADBTermios::new(std::io::stdin())?;
                    adb_termios.set_adb_termios()?;
                    device.shell(&mut std::io::stdin(), Box::new(std::io::stdout()))?;
                }

                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    device.shell(&mut std::io::stdin(), Box::new(std::io::stdout()))?;
                }
            } else {
                let commands: Vec<&str> = commands.iter().map(|v| v.as_str()).collect();
                device.shell_command(&commands, &mut std::io::stdout())?;
            }
        }
        DeviceCommands::Pull {
            source,
            destination,
        } => {
            let mut output = File::create(Path::new(&destination))?;
            device.pull(&source, &mut output)?;
            log::info!("Downloaded {source} as {destination}");
        }
        DeviceCommands::Stat { path } => {
            let stat_response = device.stat(&path)?;
            println!("{}", stat_response);
        }
        DeviceCommands::Reboot { reboot_type } => {
            log::info!("Reboots device in mode {:?}", reboot_type);
            device.reboot(reboot_type.into())?
        }
        DeviceCommands::Push { filename, path } => {
            let mut input = File::open(Path::new(&filename))?;
            device.push(&mut input, &path)?;
            log::info!("Uploaded {filename} to {path}");
        }
        DeviceCommands::Run { package, activity } => {
            let output = device.run_activity(&package, &activity)?;
            std::io::stdout().write_all(&output)?;
        }
        DeviceCommands::Install { path } => {
            log::info!("Starting installation of APK {}...", path.display());
            device.install(&path)?;
        }
        DeviceCommands::Uninstall { package } => {
            log::info!("Uninstalling the package {}...", package);
            device.uninstall(&package)?;
        }
        DeviceCommands::Framebuffer { path } => {
            device.framebuffer(&path)?;
            log::info!("Successfully dumped framebuffer at path {path}");
        }
    }

    Ok(())
}
