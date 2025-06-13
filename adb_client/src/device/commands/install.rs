use std::{fs::File, path::Path};

use crate::{
    ADBMessageTransport, Result,
    device::{MessageWriter, adb_message_device::ADBMessageDevice},
    utils::check_extension_is_apk,
};

impl<T: ADBMessageTransport> ADBMessageDevice<T> {
    pub(crate) fn install(&mut self, apk_path: impl AsRef<Path>) -> Result<()> {
        let apk_path = apk_path.as_ref();
        let mut apk_file = File::open(apk_path)?;

        check_extension_is_apk(apk_path)?;

        let file_size = apk_file.metadata()?.len();

        self.open_session(format!("exec:cmd package 'install' -S {}\0", file_size).as_bytes())?;

        let local_id = self.get_local_id()?;
        let remote_id = self.get_remote_id()?;

        let mut writer = MessageWriter::new(self.get_transport(), local_id, remote_id);

        std::io::copy(&mut apk_file, &mut writer)?;

        let final_status = self.get_transport().read_message()?;

        match final_status.into_payload().as_slice() {
            b"Success\n" => {
                log::info!(
                    "APK file {} successfully installed",
                    apk_path.display()
                );
                Ok(())
            }
            d => Err(crate::RustADBError::ADBRequestFailed(String::from_utf8(
                d.to_vec(),
            )?)),
        }
    }
}
