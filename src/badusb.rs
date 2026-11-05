use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadUsbVerdict {
    Normal,
    SuspiciousKeystrokeBurst { cpm: u32, duration_ms: u64 },
    AutomatedInjectionDetected { cpm: u32 },
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

pub struct BadUsbDetector {
    key_timestamps: Vec<Instant>,
    window_duration_secs: u64,
    cpm_threshold_warning: u32,
    cpm_threshold_critical: u32,
    events: Arc<Mutex<Vec<UsbAttackEvent>>>,
}

impl BadUsbDetector {
    pub fn new(events: Arc<Mutex<Vec<UsbAttackEvent>>>) -> Self {
        Self {
            key_timestamps: Vec::with_capacity(500),
            window_duration_secs: 2,
            cpm_threshold_warning: 900,  // ~15 keystrokes per second (inhuman for sustained typing)
            cpm_threshold_critical: 1800, // ~30 keystrokes per second (typical Rubber Ducky / HID injection)
            events,
        }
    }

    /// Record a physical/virtual key press timestamp and analyze velocity
    pub fn record_keystroke(&mut self, now: Instant) -> BadUsbVerdict {
        self.key_timestamps.push(now);

        // Prune entries older than sliding window
        let cutoff = now.checked_sub(std::time::Duration::from_secs(self.window_duration_secs)).unwrap_or(now);
        self.key_timestamps.retain(|&t| t >= cutoff);

        let count = self.key_timestamps.len();
        if count < 10 {
            return BadUsbVerdict::Normal;
        }

        // Calculate Characters Per Minute (CPM)
        // count keystrokes in window_duration_secs -> count * (60 / window_duration_secs)
        let cpm = (count as u64 * 60 / self.window_duration_secs) as u32;

        if cpm >= self.cpm_threshold_critical {
            let verdict = BadUsbVerdict::AutomatedInjectionDetected { cpm };
            self.log_event(
                "🚨 DETEKSI BADUSB / HID INJECTION",
                format!("Kecepatan ketikan ekstrem terdeteksi: {} CPM ({} karakter dalam {} detik). Pola khas Rubber Ducky / Payload injeksi otomatis!", cpm, count, self.window_duration_secs),
                EventSeverity::Critical,
            );
            verdict
        } else if cpm >= self.cpm_threshold_warning {
            let verdict = BadUsbVerdict::SuspiciousKeystrokeBurst {
                cpm,
                duration_ms: self.window_duration_secs * 1000,
            };
            self.log_event(
                "⚠️ Kecepatan Ketikan Tidak Lazim",
                format!("Aktivitas ketikan tinggi terdeteksi: {} CPM. Melebihi kecepatan ketikan normal manusia.", cpm),
                EventSeverity::Warning,
            );
            verdict
        } else {
            BadUsbVerdict::Normal
        }
    }

    fn log_event(&self, title: &str, description: String, severity: EventSeverity) {
        if let Ok(mut evts) = self.events.lock() {
            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
            // Debounce if same title logged in last 3 seconds
            if let Some(last) = evts.last() {
                if last.title == title && last.timestamp == ts {
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

    pub fn reset_window(&mut self) {
        self.key_timestamps.clear();
    }
}
