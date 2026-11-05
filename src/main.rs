#![windows_subsystem = "windows"]

use std::sync::{Arc, Mutex};
use eframe::egui::Vec2;

mod anti_keylogger;
mod app;
mod badusb;
mod hook;
mod usb_monitor;

#[cfg(test)]
mod tests;

use anti_keylogger::KeyloggerDetector;
use app::KeySentinelApp;
use hook::GlobalKeyHook;

fn main() -> eframe::Result<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let detector = Arc::new(Mutex::new(KeyloggerDetector::new(events.clone())));

    // Start background low-level keyboard hook for BadUSB detection
    let hook_mgr = GlobalKeyHook::new(detector.clone());
    hook_mgr.start();

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size(Vec2::new(1080.0, 680.0))
            .with_min_inner_size(Vec2::new(800.0, 500.0))
            .with_title("KeySentinel — Anti-Keylogger & Physical USB Attack Defense"),
        ..Default::default()
    };

    eframe::run_native(
        "KeySentinel",
        options,
        Box::new(move |cc| {
            Ok(Box::new(KeySentinelApp::new(cc, detector, events)))
        }),
    )
}
