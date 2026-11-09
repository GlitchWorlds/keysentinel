#[cfg(windows)]
pub mod windows_impl {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
        HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_SZ,
    };

    const RUN_KEY_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";
    const APP_VALUE_NAME: &str = "KeySentinel";

    fn to_wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn is_autostart_enabled() -> bool {
        is_value_set(APP_VALUE_NAME)
    }

    pub fn set_autostart(enable: bool) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe_str = exe.to_string_lossy().to_string();
        let quoted_cmd = format!("\"{}\"", exe_str);

        if enable {
            set_value(APP_VALUE_NAME, &quoted_cmd)
        } else {
            delete_value(APP_VALUE_NAME)
        }
    }

    pub fn is_value_set(value_name: &str) -> bool {
        unsafe {
            let subkey_wide = to_wide_null(RUN_KEY_PATH.trim_end_matches('\0'));
            let mut hkey: HKEY = 0;
            let status = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey_wide.as_ptr(),
                0,
                KEY_READ,
                &mut hkey,
            );
            if status != 0 {
                return false;
            }

            let val_wide = to_wide_null(value_name);
            let mut val_type = 0u32;
            let mut data_len = 0u32;
            let query_status = RegQueryValueExW(
                hkey,
                val_wide.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                std::ptr::null_mut(),
                &mut data_len,
            );
            RegCloseKey(hkey);
            query_status == 0
        }
    }

    pub fn set_value(value_name: &str, data: &str) -> Result<(), String> {
        unsafe {
            let subkey_wide = to_wide_null(RUN_KEY_PATH.trim_end_matches('\0'));
            let mut hkey: HKEY = 0;
            let status = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey_wide.as_ptr(),
                0,
                KEY_WRITE,
                &mut hkey,
            );
            if status != 0 {
                return Err(format!("RegOpenKeyExW failed with error code: {}", status));
            }

            let val_wide = to_wide_null(value_name);
            let data_wide = to_wide_null(data);
            let byte_len = (data_wide.len() * std::mem::size_of::<u16>()) as u32;

            let set_status = RegSetValueExW(
                hkey,
                val_wide.as_ptr(),
                0,
                REG_SZ,
                data_wide.as_ptr() as *const u8,
                byte_len,
            );
            RegCloseKey(hkey);

            if set_status == 0 {
                Ok(())
            } else {
                Err(format!("RegSetValueExW failed with error code: {}", set_status))
            }
        }
    }

    pub fn delete_value(value_name: &str) -> Result<(), String> {
        unsafe {
            let subkey_wide = to_wide_null(RUN_KEY_PATH.trim_end_matches('\0'));
            let mut hkey: HKEY = 0;
            let status = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey_wide.as_ptr(),
                0,
                KEY_WRITE,
                &mut hkey,
            );
            if status != 0 {
                return Err(format!("RegOpenKeyExW failed with error code: {}", status));
            }

            let val_wide = to_wide_null(value_name);
            let del_status = RegDeleteValueW(hkey, val_wide.as_ptr());
            RegCloseKey(hkey);

            // 0 is ERROR_SUCCESS, 2 is ERROR_FILE_NOT_FOUND (which is fine when deleting)
            if del_status == 0 || del_status == 2 {
                Ok(())
            } else {
                Err(format!("RegDeleteValueW failed with error code: {}", del_status))
            }
        }
    }
}

#[cfg(not(windows))]
pub mod windows_impl {
    pub fn is_autostart_enabled() -> bool { false }
    pub fn set_autostart(_enable: bool) -> Result<(), String> { Ok(()) }
    pub fn is_value_set(_value_name: &str) -> bool { false }
    pub fn set_value(_value_name: &str, _data: &str) -> Result<(), String> { Ok(()) }
    pub fn delete_value(_value_name: &str) -> Result<(), String> { Ok(()) }
}

pub use windows_impl::*;
