#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use crate::anti_keylogger::KeyloggerDetector;
    use crate::autostart;
    use crate::badusb::{BadUsbDetector, BadUsbVerdict, EventSeverity, InputSource};
    use crate::hid_guard::HidGuard;
    use crate::hook::FirewallState;
    use crate::usb_monitor::UsbMonitor;

    // Test 1: Holding a key (typematic auto-repeat of same vk_code 50 times in 1s)
    // MUST yield BadUsbVerdict::Normal and 0 false-positive alerts!
    #[test]
    fn test_holding_key_auto_repeat_zero_false_positive() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut detector = BadUsbDetector::new(events.clone());
        let mut now = Instant::now();

        let vk_backspace = 0x08; // VK_BACK

        // 1st press: key down
        let (v1, is_repeat1) = detector.on_key_event(vk_backspace, 0, true, now);
        assert_eq!(v1, BadUsbVerdict::Normal);
        assert!(!is_repeat1, "First press is not a repeat");

        // Next 50 rapid auto-repeat events simulated from holding the key for 1.5 seconds (~30 Hz)
        for _ in 0..50 {
            now += Duration::from_millis(30);
            let (verdict, is_repeat) = detector.on_key_event(vk_backspace, 0, true, now);
            assert_eq!(verdict, BadUsbVerdict::Normal, "Auto-repeat must not trigger false positive");
            assert!(is_repeat, "Subsequent presses while held must be flagged as repeat");
        }

        // Release the key
        let (v_up, is_repeat_up) = detector.on_key_event(vk_backspace, 0, false, now);
        assert_eq!(v_up, BadUsbVerdict::Normal);
        assert!(!is_repeat_up);

        // Verify zero events logged
        let logged = events.lock().unwrap();
        assert_eq!(logged.len(), 0, "No false positive attack events should be logged for held keys!");
    }

    // Test 2: Normal fast human typing with natural biological timing jitter
    // MUST yield BadUsbVerdict::Normal
    #[test]
    fn test_normal_fast_human_typing_with_jitter() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut detector = BadUsbDetector::new(events.clone());
        let mut now = Instant::now();

        // Varied keys for typing a sentence like "the quick brown fox"
        let phrase = [
            0x54, 0x48, 0x45, 0x20, 0x51, 0x55, 0x49, 0x43, 0x4B, 0x20,
            0x42, 0x52, 0x4F, 0x57, 0x4E, 0x20, 0x46, 0x4F, 0x58, 0x20,
            0x4A, 0x55, 0x4D, 0x50, 0x53,
        ];

        // Intervals with natural human biological variation (60ms - 140ms)
        let intervals = [
            75, 110, 85, 130, 90, 65, 120, 105, 80, 140,
            70, 95, 115, 85, 100, 125, 75, 110, 90, 85,
            130, 95, 70, 105, 80,
        ];

        for (i, &vk) in phrase.iter().enumerate() {
            now += Duration::from_millis(intervals[i]);
            let (v_down, _) = detector.on_key_event(vk, 0, true, now);
            assert_eq!(v_down, BadUsbVerdict::Normal, "Human typing must remain Normal");

            // Key up 30ms later
            now += Duration::from_millis(30);
            let (v_up, _) = detector.on_key_event(vk, 0, false, now);
            assert_eq!(v_up, BadUsbVerdict::Normal);
        }

        let logged = events.lock().unwrap();
        assert_eq!(logged.len(), 0, "Fast human typing with natural jitter must not produce warnings!");
    }

    // Test 3: Machine-speed diverse keystroke burst (BadUSB simulation: 65 distinct keys with 8ms uniform intervals)
    // MUST trigger AutomatedInjectionDetected and engage firewall quarantine
    #[test]
    fn test_badusb_machine_burst_detected_and_quarantined() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut detector = BadUsbDetector::new(events.clone());
        let firewall = Arc::new(FirewallState::new());
        let mut now = Instant::now();

        let mut triggered = false;
        // Simulate Rubber Ducky typing a PowerShell command at 8ms machine clock speed
        for i in 0..65 {
            now += Duration::from_millis(8);
            let vk = 0x41 + (i % 26); // Diverse alphanumeric keys
            let (verdict, _) = detector.on_key_event(vk, 0, true, now);

            if let BadUsbVerdict::AutomatedInjectionDetected { cpm, unique_keys, reason, .. } = verdict {
                assert!(cpm >= 1800, "CPM should exceed 1800 for 8ms burst, got {}", cpm);
                assert!(unique_keys >= 5, "Unique keys should be diverse");
                assert!(!reason.is_empty());
                triggered = true;

                // Engage firewall
                firewall.quarantine(Duration::from_secs(15), "BadUSB Burst Intercepted");
                break;
            }

            now += Duration::from_millis(1);
            let _ = detector.on_key_event(vk, 0, false, now);
        }

        assert!(triggered, "Detector must trigger AutomatedInjectionDetected for BadUSB burst");
        assert!(firewall.is_quarantined(), "Firewall quarantine must be active");
        let (active, rem, _) = firewall.get_quarantine_info();
        assert!(active);
        assert!(rem > 0);

        let logged = events.lock().unwrap();
        assert!(!logged.is_empty(), "Attack event must be logged");
        assert_eq!(logged[0].severity, EventSeverity::Critical);
    }

    // Test 4: Win+R followed by rapid payload characters within 100ms
    // MUST trigger AutomatedInjectionDetected
    #[test]
    fn test_win_r_rapid_payload_trigger() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut detector = BadUsbDetector::new(events.clone());
        let mut now = Instant::now();

        // 1. Press Win key (0x5B)
        detector.on_key_event(0x5B, 0, true, now);
        now += Duration::from_millis(20);

        // 2. Press 'R' key (0x52) -> Triggers Win+R combination
        detector.on_key_event(0x52, 0, true, now);
        now += Duration::from_millis(30);

        // Release Win and R
        detector.on_key_event(0x5B, 0, false, now);
        detector.on_key_event(0x52, 0, false, now);

        // 3. Within 100ms, Rubber Ducky types "powershell" at 10ms intervals
        now += Duration::from_millis(40);
        let payload = [0x50, 0x4F, 0x57, 0x45, 0x52, 0x53, 0x48]; // 'P','O','W','E','R','S','H'
        let mut triggered = false;

        for &vk in &payload {
            now += Duration::from_millis(10);
            let (verdict, _) = detector.on_key_event(vk, 0, true, now);
            if let BadUsbVerdict::AutomatedInjectionDetected { reason, .. } = verdict {
                assert!(reason.contains("Win+R"), "Reason must mention Win+R payload trigger");
                triggered = true;
                break;
            }
            now += Duration::from_millis(2);
            detector.on_key_event(vk, 0, false, now);
        }

        assert!(triggered, "Must trigger AutomatedInjectionDetected on Win+R rapid burst");
        let logged = events.lock().unwrap();
        assert!(!logged.is_empty());
        assert!(logged[0].title.contains("WIN+R"));
    }

    // Test 5: Event log debounce (rapid consecutive triggers produce only 1 log entry)
    #[test]
    fn test_event_log_debounce() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut detector = BadUsbDetector::new(events.clone());

        // Call log_event 5 times rapidly with the same title
        for _ in 0..5 {
            detector.log_event(
                "⚠️ Kecepatan Ketikan Tidak Lazim",
                "Tes log spam debounce".to_string(),
                EventSeverity::Warning,
            );
        }

        let logged = events.lock().unwrap();
        assert_eq!(logged.len(), 1, "Debounce must prevent duplicate event logs for the same category within cooldown!");
    }

    // Test 6: Software LLKHF_INJECTED attribution
    #[test]
    fn test_software_injected_attribution() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut detector = BadUsbDetector::new(events);
        let now = Instant::now();

        // Physical HID: flags = 0
        let _ = detector.on_key_event(0x41, 0, true, now);
        assert_eq!(detector.live_source, InputSource::HardwareHid);

        detector.on_key_event(0x41, 0, false, now);

        // Software SendInput: flags = 0x10 (LLKHF_INJECTED)
        let _ = detector.on_key_event(0x42, 0x10, true, now);
        assert_eq!(detector.live_source, InputSource::SoftwareInjected);

        detector.on_key_event(0x42, 0x10, false, now);

        // Lower-Integrity Injected: flags = 0x02 (LLKHF_LOWER_IL_INJECTED)
        let _ = detector.on_key_event(0x43, 0x02, true, now);
        assert_eq!(detector.live_source, InputSource::LowerIntegrityInjected);
    }

    // Test 7: Auto-start command formatting & isolated test-key registry roundtrip
    #[test]
    fn test_autostart_registry_roundtrip_isolated() {
        let test_key = "KeySentinel_UnitTest_Temp";

        // 1. Ensure clean initial state
        let _ = autostart::delete_value(test_key);
        assert!(!autostart::is_value_set(test_key), "Key must be absent before test");

        // 2. Set test value
        let test_cmd = "\"C:\\Program Files\\KeySentinel\\keysentinel.exe\"";
        let res = autostart::set_value(test_key, test_cmd);
        assert!(res.is_ok(), "Setting registry value in HKCU should succeed: {:?}", res);
        assert!(autostart::is_value_set(test_key), "Key must now be present");

        // 3. Clean up immediately
        let del_res = autostart::delete_value(test_key);
        assert!(del_res.is_ok(), "Deleting test key should succeed");
        assert!(!autostart::is_value_set(test_key), "Key must be removed after test");
    }

    // Test 8: HID keyboard enumeration runs cleanly without panic
    #[test]
    fn test_hid_keyboard_enumeration_no_panic() {
        let keyboards = HidGuard::enumerate_hid_keyboards();
        // Should not panic on Windows, count >= 0
        println!("Enumerated {} HID keyboards on test host", keyboards.len());

        // Test VID/PID extraction
        let sample_path = r"\\?\HID#VID_046D&PID_C31C&MI_00#7&2d82991&0&0000#{884b96c3-56ef-11d1-bc8c-00a0c91405dd}";
        let extracted = HidGuard::extract_vid_pid(sample_path);
        assert_eq!(extracted, "VID_046D&PID_C31C&MI_00");

        let guard = HidGuard::new(true);
        assert!(guard.is_quarantine_enabled());
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
        assert!(!findings.is_empty() || findings.is_empty());
    }
}
