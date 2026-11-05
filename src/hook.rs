use std::sync::{Arc, Mutex};
use std::thread;

use windows_sys::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetMessageW, SetWindowsHookExW,
    TranslateMessage, UnhookWindowsHookEx, HHOOK, KBDLLHOOKSTRUCT, MSG,
    WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN,
};

use crate::badusb::BadUsbVerdict;
use crate::anti_keylogger::KeyloggerDetector;

// Global state for low-level hook
// In windows-sys 0.52, HHOOK is isize
static mut HOOK_HANDLE: HHOOK = 0;
static mut DETECTOR_INSTANCE: Option<Arc<Mutex<KeyloggerDetector>>> = None;

unsafe extern "system" fn low_level_keyboard_proc(
    n_code: i32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    if n_code >= 0 && (w_param as u32 == WM_KEYDOWN || w_param as u32 == WM_SYSKEYDOWN) {
        let _kbd = *(l_param as *const KBDLLHOOKSTRUCT);
        if let Some(ref detector_arc) = DETECTOR_INSTANCE {
            if let Ok(mut detector) = detector_arc.lock() {
                let verdict = detector.on_keystroke();
                if let BadUsbVerdict::AutomatedInjectionDetected { cpm } = verdict {
                    eprintln!("🚨 [KeySentinel] BadUSB Injection intercepted: {} CPM!", cpm);
                }
            }
        }
    }
    CallNextHookEx(HOOK_HANDLE, n_code, w_param, l_param)
}

pub struct GlobalKeyHook {
    detector: Arc<Mutex<KeyloggerDetector>>,
}

impl GlobalKeyHook {
    pub fn new(detector: Arc<Mutex<KeyloggerDetector>>) -> Self {
        Self { detector }
    }

    pub fn start(&self) {
        let det = self.detector.clone();
        thread::spawn(move || unsafe {
            DETECTOR_INSTANCE = Some(det);
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
