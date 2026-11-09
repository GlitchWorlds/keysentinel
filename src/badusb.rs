use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InputSource {
    HardwareHid,
    SoftwareInjected,
    LowerIntegrityInjected,
}

impl std::fmt::Display for InputSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputSource::HardwareHid => write!(f, "Hardware USB HID"),
            InputSource::SoftwareInjected => write!(f, "Software SendInput"),
            InputSource::LowerIntegrityInjected => write!(f, "Lower-Integrity Injected"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BadUsbVerdict {
    Normal,
    SuspiciousKeystrokeBurst {
        cpm: u32,
        jitter_ms: f64,
        unique_keys: usize,
        source: InputSource,
    },
    AutomatedInjectionDetected {
        cpm: u32,
        jitter_ms: f64,
        unique_keys: usize,
        source: InputSource,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct UsbAttackEvent {
    pub timestamp: String,
    pub title: String,
    pub description: String,
    pub severity: EventSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone)]
pub struct KeystrokeRecord {
    pub timestamp: Instant,
    pub vk_code: u32,
    #[allow(dead_code)]
    pub source: InputSource,
}

pub struct BadUsbDetector {
    history: Vec<KeystrokeRecord>,
    held_keys: HashSet<u32>,
    window_duration_secs: f64,
    cpm_threshold_warning: u32,
    cpm_threshold_critical: u32,
    last_win_pressed: Option<Instant>,
    last_win_r_triggered: Option<Instant>,
    last_logged_instants: HashMap<String, Instant>,
    events: Arc<Mutex<Vec<UsbAttackEvent>>>,

    // Live telemetry for UI
    pub live_cpm: u32,
    pub live_source: InputSource,
    pub live_jitter_ms: f64,
}

impl BadUsbDetector {
    pub fn new(events: Arc<Mutex<Vec<UsbAttackEvent>>>) -> Self {
        Self {
            history: Vec::with_capacity(1000),
            held_keys: HashSet::with_capacity(64),
            window_duration_secs: 2.0,
            cpm_threshold_warning: 1350,  // Requires high CPM + machine timing consistency
            cpm_threshold_critical: 1800, // ~30+ keys/sec (Rubber Ducky / BadUSB injection)
            last_win_pressed: None,
            last_win_r_triggered: None,
            last_logged_instants: HashMap::new(),
            events,
            live_cpm: 0,
            live_source: InputSource::HardwareHid,
            live_jitter_ms: 0.0,
        }
    }

    /// Process a raw keyboard event (down/up with flags)
    pub fn on_key_event(
        &mut self,
        vk_code: u32,
        flags: u32,
        is_keydown: bool,
        now: Instant,
    ) -> (BadUsbVerdict, bool /* is_repeat */) {
        if !is_keydown {
            self.held_keys.remove(&vk_code);
            return (BadUsbVerdict::Normal, false);
        }

        let is_lower_il = (flags & 0x02) != 0;
        let is_software = (flags & 0x10) != 0;
        let source = if is_lower_il {
            InputSource::LowerIntegrityInjected
        } else if is_software {
            InputSource::SoftwareInjected
        } else {
            InputSource::HardwareHid
        };
        self.live_source = source;

        // Check if key is already held (Windows typematic auto-repeat)
        let is_repeat = self.held_keys.contains(&vk_code);
        if !is_repeat {
            self.held_keys.insert(vk_code);
        }

        // Win key tracking (VK_LWIN = 0x5B, VK_RWIN = 0x5C)
        if vk_code == 0x5B || vk_code == 0x5C {
            self.last_win_pressed = Some(now);
        }

        // Win+R check (VK_R = 0x52)
        if vk_code == 0x52 {
            let win_down = self.held_keys.contains(&0x5B) || self.held_keys.contains(&0x5C);
            let win_recent = self.last_win_pressed
                .map(|t| now.duration_since(t) <= Duration::from_millis(250))
                .unwrap_or(false);

            if win_down || win_recent {
                self.last_win_r_triggered = Some(now);
                self.last_win_pressed = None; // Reset so subsequent 'r' in payload doesn't re-trigger
                return (BadUsbVerdict::Normal, false);
            }
        }

        // Standalone modifier keys check (Shift, Ctrl, Alt, Win)
        // VK_SHIFT: 0x10, VK_CONTROL: 0x11, VK_MENU: 0x12
        // VK_LWIN: 0x5B, VK_RWIN: 0x5C
        // VK_LSHIFT: 0xA0, VK_RSHIFT: 0xA1, VK_LCONTROL: 0xA2, VK_RCONTROL: 0xA3
        // VK_LMENU: 0xA4, VK_RMENU: 0xA5
        let is_standalone_modifier = matches!(
            vk_code,
            0x10 | 0x11 | 0x12 | 0x5B | 0x5C | 0xA0 | 0xA1 | 0xA2 | 0xA3 | 0xA4 | 0xA5
        );

        if is_standalone_modifier {
            // Modifiers alone do not count as character burst CPM
            return (BadUsbVerdict::Normal, is_repeat);
        }

        // If it's a typematic repeat (holding Backspace, Arrow, Space, Delete, etc.),
        // do not add to burst history. This eliminates the #1 cause of false positives!
        if is_repeat {
            return (BadUsbVerdict::Normal, true);
        }

        // Record distinct keystroke
        let verdict = self.record_distinct_keystroke(vk_code, source, now);
        (verdict, false)
    }

    /// Record a distinct, non-repeat keystroke into the sliding window
    pub fn record_distinct_keystroke(
        &mut self,
        vk_code: u32,
        source: InputSource,
        now: Instant,
    ) -> BadUsbVerdict {
        self.history.push(KeystrokeRecord {
            timestamp: now,
            vk_code,
            source,
        });

        // Prune older than sliding window
        let cutoff = now.checked_sub(Duration::from_secs_f64(self.window_duration_secs)).unwrap_or(now);
        self.history.retain(|k| k.timestamp >= cutoff);

        let count = self.history.len();

        // Foreground app context if available
        let fg_context = Self::get_foreground_app_info()
            .map(|(proc, title)| format!(" [Aplikasi Sasaran: {} ('{}')]", proc, title))
            .unwrap_or_default();

        // Check 1: Win+R Rapid Payload Trigger
        // Win + R pressed followed within 500 ms by >= 6 rapid characters at <= 35 ms average interval
        if let Some(win_r_time) = self.last_win_r_triggered {
            if now.duration_since(win_r_time) <= Duration::from_millis(500) {
                let keys_since_win_r: Vec<&KeystrokeRecord> = self.history
                    .iter()
                    .filter(|k| k.timestamp >= win_r_time)
                    .collect();

                if keys_since_win_r.len() >= 4 {
                    let mut recent_intervals = Vec::new();
                    for w in keys_since_win_r.windows(2) {
                        let dt = w[1].timestamp.duration_since(w[0].timestamp).as_secs_f64() * 1000.0;
                        recent_intervals.push(dt);
                    }
                    let avg_dt = if !recent_intervals.is_empty() {
                        recent_intervals.iter().sum::<f64>() / recent_intervals.len() as f64
                    } else {
                        999.0
                    };

                    if avg_dt <= 35.0 {
                        let cpm = (keys_since_win_r.len() as f64 * 60.0 / (avg_dt * keys_since_win_r.len() as f64 / 1000.0).max(0.1)) as u32;
                        self.live_cpm = cpm;
                        let (_, jitter_ms) = self.calculate_timing_metrics();
                        self.live_jitter_ms = jitter_ms;

                        let verdict = BadUsbVerdict::AutomatedInjectionDetected {
                            cpm,
                            jitter_ms,
                            unique_keys: keys_since_win_r.len(),
                            source,
                            reason: "Win+R Rapid Payload Trigger (Rubber Ducky shell launch)".to_string(),
                        };
                        self.log_event(
                            "🚨 SERANGAN BADUSB: WIN+R INJEKSI KILAT",
                            format!(
                                "Injeksi payload otomatis terdeteksi sesaat setelah kombinasi Win+R! {} karakter diketik dalam tempo rata-rata {:.1} ms per tombol. Sumber: {} | CPM: {}{}. Tindakan: DIBLOKIR OTOMATIS & KARANTINA KEYBOARD.",
                                keys_since_win_r.len(),
                                avg_dt,
                                source,
                                cpm,
                                fg_context
                            ),
                            EventSeverity::Critical,
                        );
                        return verdict;
                    }
                }
            }
        }

        if count < 5 {
            self.live_cpm = (count as f64 * 60.0 / self.window_duration_secs) as u32;
            return BadUsbVerdict::Normal;
        }

        // Calculate Distinct Keypress CPM
        // If burst is concentrated in a short span (< 2s), calculate rate over that span
        let span_secs = if count >= 2 {
            let dt = now.duration_since(self.history[0].timestamp).as_secs_f64();
            dt.max(0.05)
        } else {
            1.0
        };

        let window_cpm = (count as f64 * 60.0 / self.window_duration_secs) as u32;
        let instant_cpm = (count as f64 * 60.0 / span_secs.min(self.window_duration_secs)) as u32;
        let cpm = instant_cpm.max(window_cpm);
        self.live_cpm = cpm;

        // 2. Compute Unique Key Diversity
        let unique_keys = self.history.iter().map(|k| k.vk_code).collect::<HashSet<_>>().len();

        // 3. Compute Inter-Keystroke Interval Jitter (std dev of dt in ms)
        let (mean_interval_ms, jitter_ms) = self.calculate_timing_metrics();
        self.live_jitter_ms = jitter_ms;

        // Check 2: Critical Automated Injection (CPM >= 1800 or high burst in sub-second)
        let is_rapid_burst = count >= 25 && mean_interval_ms < 20.0 && unique_keys >= 5;
        let is_high_cpm = cpm >= self.cpm_threshold_critical && unique_keys >= 4;

        if is_high_cpm || is_rapid_burst {
            let reason = if is_high_cpm {
                format!("Kecepatan mesin ekstrem ({} CPM >= 1800 CPM) dengan variasi tombol tinggi", cpm)
            } else {
                format!("Burst injeksi kilat ({} tombol dalam {:.1} ms rata-rata)", count, mean_interval_ms)
            };

            let verdict = BadUsbVerdict::AutomatedInjectionDetected {
                cpm,
                jitter_ms,
                unique_keys,
                source,
                reason: reason.clone(),
            };

            self.log_event(
                "🚨 DETEKSI BADUSB / HID INJECTION",
                format!(
                    "Injeksi otomatis terdeteksi: {} CPM ({} karakter/2 detik, {} tombol unik, jitter: {:.2} ms). Pola Rubber Ducky / BadUSB terkonfirmasi! Sumber: {}{}. Tindakan: DIBLOKIR OTOMATIS & KARANTINA KEYBOARD.",
                    cpm,
                    count,
                    unique_keys,
                    jitter_ms,
                    source,
                    fg_context
                ),
                EventSeverity::Critical,
            );
            return verdict;
        }

        // Check 3: Suspicious Keystroke Burst (Warning)
        // Requires high CPM >= 1350 with diverse keys >= 6 AND ultra-low jitter < 8.0 ms (machine-like)
        if cpm >= self.cpm_threshold_warning && unique_keys >= 6 && jitter_ms < 8.0 {
            let verdict = BadUsbVerdict::SuspiciousKeystrokeBurst {
                cpm,
                jitter_ms,
                unique_keys,
                source,
            };

            self.log_event(
                "⚠️ Kecepatan Ketikan Tidak Lazim",
                format!(
                    "Aktivitas ketikan tinggi dan sangat teratur terdeteksi: {} CPM (jitter: {:.2} ms, {} tombol unik). Sumber: {}{}. Tindakan: PERINGATAN SISTEM.",
                    cpm,
                    jitter_ms,
                    unique_keys,
                    source,
                    fg_context
                ),
                EventSeverity::Warning,
            );
            return verdict;
        }

        BadUsbVerdict::Normal
    }

    /// Calculate mean interval and standard deviation (jitter) in milliseconds
    fn calculate_timing_metrics(&self) -> (f64, f64) {
        if self.history.len() < 3 {
            return (0.0, 0.0);
        }

        let mut intervals = Vec::with_capacity(self.history.len());
        for w in self.history.windows(2) {
            let dt = w[1].timestamp.duration_since(w[0].timestamp).as_secs_f64() * 1000.0;
            // Filter simultaneous two-finger rollover chords (< 2 ms) for cleaner jitter
            if dt >= 1.0 {
                intervals.push(dt);
            }
        }

        if intervals.is_empty() {
            return (0.0, 0.0);
        }

        let count = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / count;

        let variance = intervals.iter().map(|&x| {
            let diff = x - mean;
            diff * diff
        }).sum::<f64>() / count;

        let std_dev = variance.sqrt();
        (mean, std_dev)
    }

    /// Centralized event logger with strict debounce and cooldown
    pub fn log_event(&mut self, title: &str, description: String, severity: EventSeverity) {
        let now = Instant::now();

        // 3-second cooldown per event category
        if let Some(&last_time) = self.last_logged_instants.get(title) {
            if now.duration_since(last_time) < Duration::from_secs(3) {
                return;
            }
        }
        self.last_logged_instants.insert(title.to_string(), now);

        if let Ok(mut evts) = self.events.lock() {
            let ts = chrono::Local::now().format("%H:%M:%S").to_string();

            // Debounce: check newest event at evts.first()
            if let Some(first) = evts.first() {
                if first.title == title && first.timestamp == ts {
                    return;
                }
            }

            evts.insert(0, UsbAttackEvent {
                timestamp: ts,
                title: title.to_string(),
                description,
                severity,
            });

            if evts.len() > 100 {
                evts.truncate(100);
            }
        }
    }

    #[allow(dead_code)]
    pub fn reset_window(&mut self) {
        self.history.clear();
        self.held_keys.clear();
        self.live_cpm = 0;
        self.live_jitter_ms = 0.0;
    }

    /// Query target foreground window and process name on Windows
    #[cfg(windows)]
    pub fn get_foreground_app_info() -> Option<(String, String)> {
        unsafe {
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
            };

            let hwnd = GetForegroundWindow();
            if hwnd == 0 {
                return None;
            }

            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, &mut pid);

            let mut title_buf = [0u16; 256];
            let len = GetWindowTextW(hwnd, title_buf.as_mut_ptr(), 256);
            let title = if len > 0 {
                String::from_utf16_lossy(&title_buf[..len as usize])
            } else {
                "Windows Application".to_string()
            };

            let mut sys = sysinfo::System::new();
            sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]), true);
            let proc_name = sys.process(sysinfo::Pid::from_u32(pid))
                .map(|p| p.name().to_string_lossy().to_string())
                .unwrap_or_else(|| format!("PID:{}", pid));

            Some((proc_name, title))
        }
    }

    #[cfg(not(windows))]
    pub fn get_foreground_app_info() -> Option<(String, String)> {
        None
    }
}
