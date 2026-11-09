use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetMessageW, SetWindowsHookExW,
    TranslateMessage, UnhookWindowsHookEx, HHOOK, KBDLLHOOKSTRUCT, MSG,
    WH_KEYBOARD_LL, WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
};

use crate::anti_keylogger::KeyloggerDetector;
use crate::badusb::BadUsbVerdict;

// Global state for low-level hook
static mut HOOK_HANDLE: HHOOK = 0;
static mut DETECTOR_INSTANCE: Option<Arc<Mutex<KeyloggerDetector>>> = None;
static mut FIREWALL_INSTANCE: Option<Arc<FirewallState>> = None;

#[derive(Debug)]
pub struct FirewallPolicy {
    pub block_malicious_input: AtomicBool,
    pub block_software_sendinput: AtomicBool,
    pub block_lower_il_injected: AtomicBool,
}

impl Default for FirewallPolicy {
    fn default() -> Self {
        Self {
            block_malicious_input: AtomicBool::new(true),
            block_software_sendinput: AtomicBool::new(false),
            block_lower_il_injected: AtomicBool::new(true),
        }
    }
}

pub struct FirewallState {
    pub policy: FirewallPolicy,
    pub quarantined: AtomicBool,
    pub quarantine_until: Mutex<Option<Instant>>,
    pub quarantine_reason: Mutex<String>,
    pub blocked_count: AtomicU64,
}

impl FirewallState {
    pub fn new() -> Self {
        Self {
            policy: FirewallPolicy::default(),
            quarantined: AtomicBool::new(false),
            quarantine_until: Mutex::new(None),
            quarantine_reason: Mutex::new(String::new()),
            blocked_count: AtomicU64::new(0),
        }
    }

    pub fn is_quarantined(&self) -> bool {
        if !self.quarantined.load(Ordering::Relaxed) {
            return false;
        }
        if let Ok(until_opt) = self.quarantine_until.lock() {
            if let Some(until) = *until_opt {
                if Instant::now() >= until {
                    self.quarantined.store(false, Ordering::SeqCst);
                    return false;
                }
            }
        }
        true
    }

    pub fn unblock(&self) {
        self.quarantined.store(false, Ordering::SeqCst);
        if let Ok(mut u) = self.quarantine_until.lock() {
            *u = None;
        }
        if let Ok(mut r) = self.quarantine_reason.lock() {
            *r = String::new();
        }
    }

    pub fn quarantine(&self, duration: Duration, reason: &str) {
        self.quarantined.store(true, Ordering::SeqCst);
        if let Ok(mut u) = self.quarantine_until.lock() {
            *u = Some(Instant::now() + duration);
        }
        if let Ok(mut r) = self.quarantine_reason.lock() {
            *r = reason.to_string();
        }
    }

    pub fn get_quarantine_info(&self) -> (bool, u64, String) {
        let active = self.is_quarantined();
        let rem_secs = if active {
            if let Ok(u) = self.quarantine_until.lock() {
                u.map(|t| t.saturating_duration_since(Instant::now()).as_secs()).unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };
        let reason = if active {
            self.quarantine_reason.lock().map(|r| r.clone()).unwrap_or_default()
        } else {
            String::new()
        };
        (active, rem_secs, reason)
    }
}

unsafe extern "system" fn low_level_keyboard_proc(
    n_code: i32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    if n_code < 0 {
        return CallNextHookEx(HOOK_HANDLE, n_code, w_param, l_param);
    }

    let msg = w_param as u32;
    let is_keydown = msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN;
    let is_keyup = msg == WM_KEYUP || msg == WM_SYSKEYUP;

    if !is_keydown && !is_keyup {
        return CallNextHookEx(HOOK_HANDLE, n_code, w_param, l_param);
    }

    let kbd = *(l_param as *const KBDLLHOOKSTRUCT);
    let vk_code = kbd.vkCode;
    let flags = kbd.flags;

    let is_lower_il = (flags & 0x02) != 0;
    let is_software = (flags & 0x10) != 0;

    // 1. Check active quarantine (Active Keystroke Firewall: drop all keys!)
    if let Some(ref fw) = FIREWALL_INSTANCE {
        if fw.quarantined.load(Ordering::Relaxed) {
            let mut expired = false;
            if let Ok(until_opt) = fw.quarantine_until.try_lock() {
                if let Some(until) = *until_opt {
                    if Instant::now() >= until {
                        expired = true;
                    }
                }
            }
            if expired {
                fw.quarantined.store(false, Ordering::SeqCst);
            } else {
                // Drop & swallow keystroke!
                fw.blocked_count.fetch_add(1, Ordering::Relaxed);
                return 1;
            }
        }

        // 2. Check Software Synthetic Injected block
        if is_keydown {
            if is_lower_il && fw.policy.block_lower_il_injected.load(Ordering::Relaxed) {
                fw.blocked_count.fetch_add(1, Ordering::Relaxed);
                return 1;
            }
            if is_software && fw.policy.block_software_sendinput.load(Ordering::Relaxed) {
                fw.blocked_count.fetch_add(1, Ordering::Relaxed);
                return 1;
            }
        }
    }

    // 3. Multi-signal analysis via Detector
    if let Some(ref detector_arc) = DETECTOR_INSTANCE {
        if let Ok(mut detector) = detector_arc.try_lock() {
            let verdict = detector.on_key_event(vk_code, flags, is_keydown);

            if let BadUsbVerdict::AutomatedInjectionDetected { cpm, .. } = verdict {
                eprintln!("🚨 [KeySentinel Firewall] BadUSB Injection blocked: {} CPM!", cpm);
                if let Some(ref fw) = FIREWALL_INSTANCE {
                    if fw.policy.block_malicious_input.load(Ordering::Relaxed) {
                        fw.quarantine(
                            Duration::from_secs(15),
                            "Injeksi BadUSB Kilat Terdeteksi — Keystroke Diblokir Otomatis!",
                        );
                        fw.blocked_count.fetch_add(1, Ordering::Relaxed);
                        return 1; // Drop this malicious keystroke!
                    }
                }
            }
        }
    }

    CallNextHookEx(HOOK_HANDLE, n_code, w_param, l_param)
}

pub struct GlobalKeyHook {
    detector: Arc<Mutex<KeyloggerDetector>>,
    firewall: Arc<FirewallState>,
}

impl GlobalKeyHook {
    pub fn new(detector: Arc<Mutex<KeyloggerDetector>>, firewall: Arc<FirewallState>) -> Self {
        Self { detector, firewall }
    }

    #[allow(dead_code)]
    pub fn firewall(&self) -> Arc<FirewallState> {
        self.firewall.clone()
    }

    pub fn start(&self) {
        let det = self.detector.clone();
        let fw = self.firewall.clone();

        thread::spawn(move || unsafe {
            DETECTOR_INSTANCE = Some(det);
            FIREWALL_INSTANCE = Some(fw);

            let hook = SetWindowsHookExW(
                WH_KEYBOARD_LL,
                Some(low_level_keyboard_proc),
                0 as HINSTANCE,
                0,
            );

            if hook == 0 {
                eprintln!("Gagal mengaktifkan Windows low-level keyboard hook.");
                return;
            }
            HOOK_HANDLE = hook;

            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, 0, 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            if HOOK_HANDLE != 0 {
                UnhookWindowsHookEx(HOOK_HANDLE);
                HOOK_HANDLE = 0;
            }
        });
    }
}
