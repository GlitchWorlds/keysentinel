use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::badusb::{BadUsbDetector, BadUsbVerdict, EventSeverity, InputSource, UsbAttackEvent};

#[cfg(windows)]
extern "system" {
    fn LockWorkStation() -> windows_sys::Win32::Foundation::BOOL;
}

#[derive(Debug, Clone)]
pub struct HookDetectionInfo {
    pub process_id: u32,
    pub process_name: String,
    pub hook_type: String,
    pub suspicious_score: u8,
    pub description: String,
}

pub struct KeyloggerDetector {
    badusb_detector: BadUsbDetector,
    auto_lock_on_badusb: bool,
    events: Arc<Mutex<Vec<UsbAttackEvent>>>,
    last_injection_alert: Option<Instant>,
}

impl KeyloggerDetector {
    pub fn new(events: Arc<Mutex<Vec<UsbAttackEvent>>>) -> Self {
        Self {
            badusb_detector: BadUsbDetector::new(events.clone()),
            auto_lock_on_badusb: true,
            events,
            last_injection_alert: None,
        }
    }

    pub fn set_auto_lock(&mut self, enabled: bool) {
        self.auto_lock_on_badusb = enabled;
    }

    #[allow(dead_code)]
    pub fn is_auto_lock_enabled(&self) -> bool {
        self.auto_lock_on_badusb
    }

    /// Process a captured keystroke event with full hardware/software telemetry
    pub fn on_key_event(&mut self, vk_code: u32, flags: u32, is_keydown: bool) -> BadUsbVerdict {
        let now = Instant::now();
        let (verdict, _is_repeat) = self.badusb_detector.on_key_event(vk_code, flags, is_keydown, now);

        if let BadUsbVerdict::AutomatedInjectionDetected { .. } = verdict {
            let should_lock = self.auto_lock_on_badusb
                && self.last_injection_alert.map(|t| t.elapsed().as_secs() > 8).unwrap_or(true);

            if should_lock {
                self.last_injection_alert = Some(now);
                self.lock_workstation();
            }
        }

        verdict
    }

    /// Convenience wrapper for legacy single-stroke simulation
    #[allow(dead_code)]
    pub fn on_keystroke(&mut self) -> BadUsbVerdict {
        self.on_key_event(0x41 /* 'A' */, 0, true)
    }

    pub fn live_telemetry(&self) -> (u32, InputSource, f64) {
        (
            self.badusb_detector.live_cpm,
            self.badusb_detector.live_source,
            self.badusb_detector.live_jitter_ms,
        )
    }

    #[allow(dead_code)]
    pub fn reset_window(&mut self) {
        self.badusb_detector.reset_window();
    }

    /// Emergency lock workstation to foil Rubber Ducky / BadUSB payload in milliseconds
    pub fn lock_workstation(&self) {
        #[cfg(windows)]
        unsafe {
            LockWorkStation();
        }
    }

    /// Scan running processes for potential keylogger signatures and hook candidates
    pub fn scan_processes_for_keyloggers(&self) -> Vec<HookDetectionInfo> {
        let mut suspicious = Vec::new();
        let mut sys = sysinfo::System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        let known_clean = [
            "explorer.exe",
            "dwm.exe",
            "csrss.exe",
            "taskhostw.exe",
            "ctfmon.exe",
            "sihost.exe",
            "keysentinel.exe",
            "netsentinel.exe",
            "svchost.exe",
            "searchhost.exe",
            "startmenuexperiencehost.exe",
            "textinputhost.exe",
        ];

        let suspicious_names = [
            "keylog", "logger", "hook", "spy", "stealer", "grabber", "klog", "keystroke", "agent",
        ];

        for (pid, proc_) in sys.processes() {
            let name = proc_.name().to_string_lossy().to_lowercase();
            let pid_u32 = pid.as_u32();

            if known_clean.iter().any(|&c| c == name) {
                continue;
            }

            let mut score = 0u8;
            let mut reasons = Vec::new();

            // Name heuristic
            for sn in &suspicious_names {
                if name.contains(sn) {
                    score += 50;
                    reasons.push(format!("Nama proses mengandung kata kunci mencurigakan '{}'", sn));
                    break;
                }
            }

            // Path heuristic (running from Temp or AppData or Downloads)
            if let Some(exe_path) = proc_.exe() {
                let p_str = exe_path.to_string_lossy().to_lowercase();
                if p_str.contains("\\temp\\") || p_str.contains("\\tmp\\") {
                    score += 35;
                    reasons.push("Eksekusi dari direktori Temporary".to_string());
                }
                if p_str.contains("\\appdata\\local\\temp\\") {
                    score += 40;
                    reasons.push("Dijalankan dari direktori Temp pengguna".to_string());
                }
                if p_str.contains("\\downloads\\") {
                    score += 20;
                    reasons.push("Dijalankan langsung dari folder Downloads".to_string());
                }
            } else {
                score += 15;
                reasons.push("Path executable tersembunyi atau akses terbatas".to_string());
            }

            if score >= 30 {
                suspicious.push(HookDetectionInfo {
                    process_id: pid_u32,
                    process_name: proc_.name().to_string_lossy().to_string(),
                    hook_type: if score >= 60 { "Peluang Tinggi Keylogger".to_string() } else { "Peluang Sedang".to_string() },
                    suspicious_score: score,
                    description: reasons.join("; "),
                });
            }
        }

        suspicious.sort_by(|a, b| b.suspicious_score.cmp(&a.suspicious_score));

        // If high-threat keyloggers found, log an event
        if let Some(highest) = suspicious.first() {
            if highest.suspicious_score >= 60 {
                if let Ok(mut evts) = self.events.lock() {
                    let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                    let title = "🕵️ Potensi Keylogger Terdeteksi";
                    if evts.first().map(|e| e.title != title).unwrap_or(true) {
                        evts.insert(0, UsbAttackEvent {
                            timestamp: ts,
                            title: title.to_string(),
                            description: format!("Proses '{}' (PID: {}) dicurigai: {}", highest.process_name, highest.process_id, highest.description),
                            severity: EventSeverity::Warning,
                        });
                        if evts.len() > 100 {
                            evts.truncate(100);
                        }
                    }
                }
            }
        }

        suspicious
    }
}
