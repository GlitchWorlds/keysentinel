use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HidKeyboardDevice {
    pub device_path: String,
    pub vid_pid: String,
    pub friendly_name: String,
}

pub struct HidGuard {
    trusted_devices: HashSet<String>,
    quarantine_enabled: bool,
}

impl HidGuard {
    pub fn new(quarantine_enabled: bool) -> Self {
        let current = Self::enumerate_hid_keyboards();
        let mut trusted = HashSet::new();
        for dev in current {
            trusted.insert(dev.device_path);
        }
        Self {
            trusted_devices: trusted,
            quarantine_enabled,
        }
    }

    #[allow(dead_code)]
    pub fn is_quarantine_enabled(&self) -> bool {
        self.quarantine_enabled
    }

    pub fn set_quarantine_enabled(&mut self, enabled: bool) {
        self.quarantine_enabled = enabled;
    }

    pub fn trusted_count(&self) -> usize {
        self.trusted_devices.len()
    }

    pub fn check_new_keyboards(&mut self) -> Vec<HidKeyboardDevice> {
        let current = Self::enumerate_hid_keyboards();
        let mut new_keyboards = Vec::new();
        for dev in current {
            if !self.trusted_devices.contains(&dev.device_path) {
                new_keyboards.push(dev);
            }
        }
        new_keyboards
    }

    #[allow(dead_code)]
    pub fn trust_device(&mut self, device_path: &str) {
        self.trusted_devices.insert(device_path.to_string());
    }

    pub fn trust_all_current(&mut self) {
        let current = Self::enumerate_hid_keyboards();
        for dev in current {
            self.trusted_devices.insert(dev.device_path);
        }
    }

    /// Enumerate all connected USB HID Keyboards using Win32 Raw Input API
    pub fn enumerate_hid_keyboards() -> Vec<HidKeyboardDevice> {
        let mut keyboards = Vec::new();

        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::UI::Input::{
                GetRawInputDeviceInfoW, GetRawInputDeviceList,
                RAWINPUTDEVICELIST, RIDI_DEVICENAME, RIM_TYPEKEYBOARD,
            };

            let mut device_count = 0u32;
            let struct_size = std::mem::size_of::<RAWINPUTDEVICELIST>() as u32;

            let res = GetRawInputDeviceList(std::ptr::null_mut(), &mut device_count, struct_size);
            if res == u32::MAX || device_count == 0 {
                return keyboards;
            }

            let mut raw_devices: Vec<RAWINPUTDEVICELIST> = Vec::with_capacity(device_count as usize);
            raw_devices.set_len(device_count as usize);

            let fetched = GetRawInputDeviceList(raw_devices.as_mut_ptr(), &mut device_count, struct_size);
            if fetched == u32::MAX {
                return keyboards;
            }

            for dev in raw_devices.iter().take(fetched as usize) {
                if dev.dwType == RIM_TYPEKEYBOARD {
                    let mut name_len = 0u32;
                    // First call: get character count needed
                    GetRawInputDeviceInfoW(
                        dev.hDevice,
                        RIDI_DEVICENAME,
                        std::ptr::null_mut(),
                        &mut name_len,
                    );

                    if name_len > 0 {
                        let mut name_buf: Vec<u16> = vec![0u16; name_len as usize];
                        let copied = GetRawInputDeviceInfoW(
                            dev.hDevice,
                            RIDI_DEVICENAME,
                            name_buf.as_mut_ptr() as *mut _,
                            &mut name_len,
                        );

                        if copied != u32::MAX && copied > 0 {
                            let len = name_buf.iter().position(|&c| c == 0).unwrap_or(copied as usize);
                            let path = String::from_utf16_lossy(&name_buf[..len]);

                            let vid_pid = Self::extract_vid_pid(&path);
                            let friendly = if vid_pid.is_empty() {
                                "Standard HID Keyboard".to_string()
                            } else {
                                format!("USB HID Keyboard ({})", vid_pid)
                            };

                            keyboards.push(HidKeyboardDevice {
                                device_path: path,
                                vid_pid,
                                friendly_name: friendly,
                            });
                        }
                    }
                }
            }
        }

        keyboards
    }

    pub fn extract_vid_pid(path: &str) -> String {
        let upper = path.to_uppercase();
        if let Some(vid_idx) = upper.find("VID_") {
            let slice = &upper[vid_idx..];
            let end_idx = slice.find('#').unwrap_or(slice.len());
            let part = &slice[..end_idx];
            return part.to_string();
        }
        String::new()
    }
}
