use std::fs;
use std::path::PathBuf;

// Windows Drive Types
pub const DRIVE_REMOVABLE: u32 = 2;

#[derive(Debug, Clone)]
pub struct UsbDriveInfo {
    pub letter: String,
    pub volume_name: String,
    pub file_system: String,
    pub total_space_mb: u64,
    pub free_space_mb: u64,
    pub suspicious_findings: Vec<String>,
}

pub struct UsbMonitor {
    known_drives: Vec<String>,
}

impl UsbMonitor {
    pub fn new() -> Self {
        let initial_drives = Self::get_available_removable_drives();
        Self {
            known_drives: initial_drives.iter().map(|d| d.letter.clone()).collect(),
        }
    }

    /// Check for newly inserted removable USB drives since last scan
    pub fn check_new_insertions(&mut self) -> (Vec<UsbDriveInfo>, Vec<UsbDriveInfo>) {
        let current_drives = Self::get_available_removable_drives();
        let mut new_drives = Vec::new();

        for drive in &current_drives {
            if !self.known_drives.contains(&drive.letter) {
                new_drives.push(drive.clone());
            }
        }

        self.known_drives = current_drives.iter().map(|d| d.letter.clone()).collect();
        (new_drives, current_drives)
    }

    /// Inspect a USB drive for malicious payloads (autorun.inf, LNK shortcut exploits, hidden exe)
    pub fn inspect_drive(path_str: &str) -> Vec<String> {
        let mut findings = Vec::new();
        let root = PathBuf::from(path_str);

        if !root.exists() {
            return findings;
        }

        // 1. Check for autorun.inf
        let autorun_path = root.join("autorun.inf");
        if autorun_path.exists() {
            findings.push("Ditemukan berkas 'autorun.inf' (potensi eksekusi otomatis saat USB dicolok)".to_string());
            if let Ok(content) = fs::read_to_string(&autorun_path) {
                if content.to_lowercase().contains("open=") || content.to_lowercase().contains("shellexecute=") {
                    findings.push("🚨 'autorun.inf' berisi perintah eksekusi otomatis berkas!".to_string());
                }
            }
        }

        // 2. Scan root directory for suspicious files
        if let Ok(entries) = fs::read_dir(&root) {
            for entry in entries.flatten() {
                let p = entry.path();
                let file_name = p.file_name().unwrap_or_default().to_string_lossy().to_lowercase();

                // Suspicious extensions
                if file_name.ends_with(".lnk") {
                    findings.push(format!("Shortcut mencurigakan di root USB: '{}' (potensi LNK exploit)", file_name));
                } else if file_name.ends_with(".vbs") || file_name.ends_with(".js") || file_name.ends_with(".hta") {
                    findings.push(format!("Skrip berbahaya terdeteksi: '{}'", file_name));
                } else if file_name.ends_with(".bat") || file_name.ends_with(".cmd") || file_name.ends_with(".ps1") {
                    findings.push(format!("Skrip terminal terdeteksi di root USB: '{}'", file_name));
                } else if file_name.ends_with(".exe") || file_name.ends_with(".scr") || file_name.ends_with(".pif") {
                    findings.push(format!("Berkas executable terdeteksi langsung di USB: '{}'", file_name));
                }
            }
        }

        findings
    }

    /// List all removable drives on the system
    pub fn get_available_removable_drives() -> Vec<UsbDriveInfo> {
        let mut list = Vec::new();

        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::Storage::FileSystem::{
                GetDriveTypeW, GetVolumeInformationW,
            };

            // Check drive letters D to Z
            for letter in b'D'..=b'Z' {
                let drive_str = format!("{}:\\\0", letter as char);
                let wide_drive: Vec<u16> = drive_str.encode_utf16().collect();
                let drive_type = GetDriveTypeW(wide_drive.as_ptr());

                if drive_type == DRIVE_REMOVABLE {
                    let mut vol_name = [0u16; 260];
                    let mut fs_name = [0u16; 260];
                    let mut serial = 0u32;
                    let mut max_comp = 0u32;
                    let mut flags = 0u32;

                    let ok = GetVolumeInformationW(
                        wide_drive.as_ptr(),
                        vol_name.as_mut_ptr(),
                        vol_name.len() as u32,
                        &mut serial,
                        &mut max_comp,
                        &mut flags,
                        fs_name.as_mut_ptr(),
                        fs_name.len() as u32,
                    );

                    let letter_str = format!("{}:", letter as char);
                    let mut volume_label = String::new();
                    let mut file_system = String::new();

                    if ok != 0 {
                        let len_vol = vol_name.iter().position(|&c| c == 0).unwrap_or(vol_name.len());
                        volume_label = String::from_utf16_lossy(&vol_name[..len_vol]);

                        let len_fs = fs_name.iter().position(|&c| c == 0).unwrap_or(fs_name.len());
                        file_system = String::from_utf16_lossy(&fs_name[..len_fs]);
                    }

                    let findings = Self::inspect_drive(&format!("{}:\\", letter as char));

                    list.push(UsbDriveInfo {
                        letter: letter_str,
                        volume_name: if volume_label.is_empty() { "USB Drive".to_string() } else { volume_label },
                        file_system: if file_system.is_empty() { "FAT32/NTFS".to_string() } else { file_system },
                        total_space_mb: 0,
                        free_space_mb: 0,
                        suspicious_findings: findings,
                    });
                }
            }
        }

        list
    }

    /// Query current Windows USB storage block status via Registry
    /// HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR -> Start (3 = Enabled, 4 = Disabled)
    pub fn is_usb_storage_blocked() -> bool {
        #[cfg(windows)]
        {
            use std::process::Command;
            let output = Command::new("reg")
                .args(["query", r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR", "/v", "Start"])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                return stdout.contains("0x4");
            }
        }
        false
    }

    /// Toggle USB storage block status (Requires Admin)
    pub fn set_usb_storage_blocked(block: bool) -> Result<(), String> {
        #[cfg(windows)]
        {
            use std::process::Command;
            let val = if block { "4" } else { "3" };
            let output = Command::new("reg")
                .args([
                    "add",
                    r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
                    "/v",
                    "Start",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    val,
                    "/f",
                ])
                .output();

            match output {
                Ok(out) => {
                    if out.status.success() {
                        Ok(())
                    } else {
                        let err = String::from_utf8_lossy(&out.stderr);
                        Err(format!("Gagal mengubah registry USBSTOR (butuh hak Administrator): {}", err.trim()))
                    }
                }
                Err(e) => Err(format!("Gagal menjalankan reg command: {}", e)),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = block;
            Ok(())
        }
    }
}
