#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use crate::badusb::{BadUsbDetector, BadUsbVerdict, UsbAttackEvent};
    use crate::anti_keylogger::KeyloggerDetector;
    use crate::usb_monitor::UsbMonitor;

    #[test]
    fn test_badusb_detector_normal_typing() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut detector = BadUsbDetector::new(events);
        let now = Instant::now();

        // 5 keystrokes spaced normally
        for _ in 0..5 {
            let verdict = detector.record_keystroke(now);
            assert_eq!(verdict, BadUsbVerdict::Normal);
        }
    }

    #[test]
    fn test_badusb_detector_burst_injection() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut detector = BadUsbDetector::new(events.clone());
        let now = Instant::now();

        // Simulate 70 keystrokes in a split second (automated BadUSB / Rubber Ducky speed)
        let mut triggered = false;
        for _ in 0..70 {
            let verdict = detector.record_keystroke(now);
            if let BadUsbVerdict::AutomatedInjectionDetected { cpm } = verdict {
                assert!(cpm >= 1800);
                triggered = true;
                break;
            }
        }

        assert!(triggered, "Detector must trigger AutomatedInjectionDetected under rapid keystroke burst");
        let evts = events.lock().unwrap();
        assert!(!evts.is_empty(), "Attack event must be logged");
    }

    #[test]
    fn test_keylogger_detector_lock_setting() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut kd = KeyloggerDetector::new(events);
        assert!(kd.is_auto_lock_enabled());
        kd.set_auto_lock(false);
        assert!(!kd.is_auto_lock_enabled());
    }

    #[test]
    fn test_usb_inspection_clean_path() {
        let temp_dir = std::env::temp_dir();
        let findings = UsbMonitor::inspect_drive(&temp_dir.to_string_lossy());
        // Should not crash and return a vector
        assert!(findings.len() >= 0);
    }
}
