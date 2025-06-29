use std::{fs::File, io::Write};

use adb_client::ADBServerDevice;
use anyhow::{Result, anyhow};

use crate::models::LocalDeviceCommand;

pub fn handle_local_commands(
    mut device: ADBServerDevice,
    local_device_commands: LocalDeviceCommand,
) -> Result<()> {
    match local_device_commands {
        LocalDeviceCommand::HostFeatures => {
            let features = device
                .host_features()?
                .iter()
                .map(|v| v.to_string())
                .reduce(|a, b| format!("{a},{b}"))
                .ok_or(anyhow!("cannot list features"))?;
            log::info!("Available host features: {features}");

            Ok(())
        }
        LocalDeviceCommand::List { path } => Ok(device.list(path)?),
        LocalDeviceCommand::Logcat { path } => {
            if let Some(path) = path {
                let f = File::create(path)?;
                Ok(device.get_logs(f)?)
            } else {
                Ok(device.get_logs(std::io::stdout())?)
            }
        }
    }
}
