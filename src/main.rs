#![windows_subsystem = "windows"]

use std::sync::{Arc, Mutex};
use eframe::egui::Vec2;

mod anti_keylogger;
mod app;
mod autostart;
mod badusb;
mod hid_guard;
mod hook;
mod usb_monitor;

#[cfg(test)]
mod tests;

use anti_keylogger::KeyloggerDetector;
use app::KeySentinelApp;
use hook::{FirewallState, GlobalKeyHook};

fn main() -> eframe::Result<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let detector = Arc::new(Mutex::new(KeyloggerDetector::new(events.clone())));
    let firewall = Arc::new(FirewallState::new());

    // Start background low-level keyboard hook for BadUSB detection & active keystroke firewall
    let hook_mgr = GlobalKeyHook::new(detector.clone(), firewall.clone());
    hook_mgr.start();

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size(Vec2::new(1080.0, 720.0))
            .with_min_inner_size(Vec2::new(800.0, 520.0))
            .with_title("KeySentinel v1.1.0 — Active Keystroke Firewall & Physical Attack Defense"),
        ..Default::default()
    };

    let app_detector = detector.clone();
    let app_events = events.clone();
    let app_firewall = firewall.clone();

    eframe::run_native(
        "KeySentinel",
        options,
        Box::new(move |cc| {
            Ok(Box::new(KeySentinelApp::new(cc, app_detector, app_events, app_firewall)))
        }),
    )
}
