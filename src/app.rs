use std::fs;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText, ScrollArea, Vec2};

use crate::anti_keylogger::{HookDetectionInfo, KeyloggerDetector};
use crate::autostart;
use crate::badusb::{EventSeverity, InputSource, UsbAttackEvent};
use crate::hid_guard::HidGuard;
use crate::hook::FirewallState;
use crate::usb_monitor::{UsbDriveInfo, UsbMonitor};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(default)]
pub struct AppConfig {
    pub auto_lock_on_badusb: bool,
    pub usb_storage_lock: bool,
    pub theme: String, // "system", "dark", "light"
    pub block_malicious_input: bool,
    pub quarantine_new_hid_keyboard: bool,
    pub block_win_r_rapid: bool,
    pub block_software_sendinput: bool,
    pub block_lower_il_injected: bool,
    pub autostart_on_boot: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_lock_on_badusb: true,
            usb_storage_lock: false,
            theme: "system".to_string(),
            block_malicious_input: true,
            quarantine_new_hid_keyboard: true,
            block_win_r_rapid: true,
            block_software_sendinput: false,
            block_lower_il_injected: true,
            autostart_on_boot: false,
        }
    }
}

impl AppConfig {
    pub fn config_path() -> PathBuf {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let p = PathBuf::from(appdata).join("KeySentinel");
            let _ = fs::create_dir_all(&p);
            p.join("config.json")
        } else {
            PathBuf::from("config.json")
        }
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        let mut config: AppConfig = if let Ok(content) = fs::read_to_string(path) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            AppConfig::default()
        };

        // Sync autostart status with Windows Registry
        config.autostart_on_boot = autostart::is_autostart_enabled();
        config
    }

    pub fn save(&self) {
        let path = Self::config_path();
        if let Ok(content) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, content);
        }
    }
}

pub struct KeySentinelApp {
    config: AppConfig,
    detector: Arc<Mutex<KeyloggerDetector>>,
    usb_monitor: UsbMonitor,
    hid_guard: HidGuard,
    events: Arc<Mutex<Vec<UsbAttackEvent>>>,
    firewall: Arc<FirewallState>,

    // State
    removable_drives: Vec<UsbDriveInfo>,
    suspicious_hooks: Vec<HookDetectionInfo>,
    is_usb_blocked: bool,
    status_text: String,
    last_scan: Instant,
    show_settings: bool,
    show_info_guide: bool,

    system_visuals: egui::Visuals,
}

impl KeySentinelApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        detector: Arc<Mutex<KeyloggerDetector>>,
        events: Arc<Mutex<Vec<UsbAttackEvent>>>,
        firewall: Arc<FirewallState>,
    ) -> Self {
        let config = AppConfig::load();
        let system_visuals = cc.egui_ctx.style().visuals.clone();

        match config.theme.as_str() {
            "dark" => cc.egui_ctx.set_visuals(egui::Visuals::dark()),
            "light" => cc.egui_ctx.set_visuals(egui::Visuals::light()),
            _ => cc.egui_ctx.set_visuals(system_visuals.clone()),
        }

        // Sync initial firewall policies from saved config
        firewall.policy.block_malicious_input.store(config.block_malicious_input, Ordering::Relaxed);
        firewall.policy.block_software_sendinput.store(config.block_software_sendinput, Ordering::Relaxed);
        firewall.policy.block_lower_il_injected.store(config.block_lower_il_injected, Ordering::Relaxed);

        if let Ok(mut det) = detector.lock() {
            det.set_auto_lock(config.auto_lock_on_badusb);
        }

        let is_usb_blocked = UsbMonitor::is_usb_storage_blocked();
        let mut usb_monitor = UsbMonitor::new();
        let (_, drives) = usb_monitor.check_new_insertions();

        let hid_guard = HidGuard::new(config.quarantine_new_hid_keyboard);

        let initial_hooks = {
            if let Ok(det) = detector.lock() {
                det.scan_processes_for_keyloggers()
            } else {
                Vec::new()
            }
        };

        Self {
            config,
            detector,
            usb_monitor,
            hid_guard,
            events,
            firewall,
            removable_drives: drives,
            suspicious_hooks: initial_hooks,
            is_usb_blocked,
            status_text: "KeySentinel v1.1.0 aktif. Active Keystroke Firewall & Zero-Trust HID Guard siaga.".to_string(),
            last_scan: Instant::now(),
            show_settings: false,
            show_info_guide: false,
            system_visuals,
        }
    }

    pub fn apply_theme(&self, ctx: &egui::Context) {
        match self.config.theme.as_str() {
            "dark" => ctx.set_visuals(egui::Visuals::dark()),
            "light" => ctx.set_visuals(egui::Visuals::light()),
            _ => ctx.set_visuals(self.system_visuals.clone()),
        }
    }

    pub fn refresh_all(&mut self) {
        // 1. Audit Removable USB Storage Drives
        let (new_drives, all_drives) = self.usb_monitor.check_new_insertions();
        self.removable_drives = all_drives;

        for d in new_drives {
            if let Ok(mut evts) = self.events.lock() {
                let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                let has_threat = !d.suspicious_findings.is_empty();
                evts.insert(0, UsbAttackEvent {
                    timestamp: ts,
                    title: format!("💾 USB Terpasang ({})", d.letter),
                    description: format!(
                        "Drive USB '{}' terdeteksi (Total: {} MB). Temuan: {}",
                        d.volume_name,
                        d.total_space_mb,
                        if has_threat { d.suspicious_findings.join(", ") } else { "Tidak ada payload mencurigakan di root".to_string() }
                    ),
                    severity: if has_threat { EventSeverity::Critical } else { EventSeverity::Info },
                });
            }
        }

        // 2. Audit New HID Keyboards (Zero-Trust BadUSB Guard)
        let new_keyboards = self.hid_guard.check_new_keyboards();
        if !new_keyboards.is_empty() {
            for kb in new_keyboards {
                let vid_pid = if kb.vid_pid.is_empty() { "VID/PID Tidak Dikenal" } else { &kb.vid_pid };
                let quarantined = self.config.quarantine_new_hid_keyboard;

                if let Ok(mut evts) = self.events.lock() {
                    let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                    evts.insert(0, UsbAttackEvent {
                        timestamp: ts,
                        title: "⌨️ Keyboard USB Baru Terdeteksi".to_string(),
                        description: format!(
                            "Perangkat HID Keyboard baru terpasang ({}). {}",
                            vid_pid,
                            if quarantined {
                                "Zero-Trust Guard: Karantina input 15 detik aktif. Verifikasi dengan mouse jika ini keyboard sah."
                            } else {
                                "Peringatan: Perangkat diizinkan langsung (Zero-Trust Guard nonaktif)."
                            }
                        ),
                        severity: if quarantined { EventSeverity::Critical } else { EventSeverity::Warning },
                    });
                }

                if quarantined {
                    self.firewall.quarantine(
                        Duration::from_secs(15),
                        &format!("Keyboard USB Baru Dicolok ({}) — Menunggu Verifikasi", vid_pid),
                    );
                }
            }
        }

        // 3. Scan Suspicious Process Hooks
        if let Ok(det) = self.detector.lock() {
            self.suspicious_hooks = det.scan_processes_for_keyloggers();
        }

        self.is_usb_blocked = UsbMonitor::is_usb_storage_blocked();
        self.last_scan = Instant::now();
        self.status_text = format!(
            "Pembaruan selesai. {} drive USB | {} keyboard HID | {} proses diperiksa.",
            self.removable_drives.len(),
            self.hid_guard.trusted_count(),
            self.suspicious_hooks.len()
        );
    }
}

impl eframe::App for KeySentinelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_theme(ctx);
        let is_dark = ctx.style().visuals.dark_mode;

        // Auto-refresh scan every 2 seconds
        if self.last_scan.elapsed() >= Duration::from_secs(2) {
            self.refresh_all();
        }

        // Request repaint so live CPM and quarantine countdown update smoothly
        ctx.request_repaint_after(Duration::from_millis(500));

        // Header Panel
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let brand_color = if is_dark {
                    Color32::from_rgb(0, 220, 255)
                } else {
                    Color32::from_rgb(0, 120, 210)
                };
                ui.heading(RichText::new("🛡️ KeySentinel").size(20.0).strong().color(brand_color));
                ui.label(RichText::new("v1.1.0 | Active Keystroke Firewall & Physical Attack Defense").color(ui.visuals().weak_text_color()));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⚙️ Pengaturan").clicked() {
                        self.show_settings = !self.show_settings;
                    }

                    if ui.button("ℹ️ Panduan").clicked() {
                        self.show_info_guide = !self.show_info_guide;
                    }

                    // Theme toggle
                    let theme_label = match self.config.theme.as_str() {
                        "dark" => "🌙 Gelap",
                        "light" => "☀️ Terang",
                        _ => "🖥️ Sistem",
                    };
                    if ui.button(theme_label).on_hover_text("Ubah Tema (Sistem / Gelap / Terang)").clicked() {
                        self.config.theme = match self.config.theme.as_str() {
                            "system" => "dark".to_string(),
                            "dark" => "light".to_string(),
                            "light" => "system".to_string(),
                            _ => "dark".to_string(),
                        };
                        self.config.save();
                        self.apply_theme(ctx);
                    }

                    if ui.button("🔄 Segarkan").clicked() {
                        self.refresh_all();
                    }

                    // Emergency Lock Button
                    let lock_btn_color = if is_dark { Color32::from_rgb(255, 80, 80) } else { Color32::from_rgb(200, 20, 20) };
                    if ui.button(RichText::new("🔒 Kunci Layar Cepat").color(lock_btn_color).strong()).on_hover_text("Segera kunci workstation Windows jika melihat orang mencurigakan mencolok USB!").clicked() {
                        if let Ok(det) = self.detector.lock() {
                            det.lock_workstation();
                        }
                    }
                });
            });

            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);

            // Protection Status Dashboard (Row 1)
            ui.horizontal(|ui| {
                // Keystroke Firewall Status
                let is_fw_active = self.config.block_malicious_input;
                let blocked_keys = self.firewall.blocked_count.load(Ordering::Relaxed);
                let fw_badge = if is_fw_active {
                    let col = if is_dark { Color32::from_rgb(80, 220, 100) } else { Color32::from_rgb(0, 140, 30) };
                    RichText::new(format!("🛡️ Firewall Ketikan: AKTIF (Blokir Otomatis) | Diblokir: {} ketikan", blocked_keys)).color(col).strong()
                } else {
                    let col = if is_dark { Color32::GOLD } else { Color32::from_rgb(180, 110, 0) };
                    RichText::new("🟡 Firewall Ketikan: HANYA PANTAU").color(col)
                };
                ui.label(fw_badge);

                ui.separator();

                // HID Keyboard Zero-Trust Status
                let hid_count = self.hid_guard.trusted_count();
                let hid_badge_color = if self.config.quarantine_new_hid_keyboard {
                    if is_dark { Color32::from_rgb(100, 200, 255) } else { Color32::from_rgb(20, 120, 210) }
                } else {
                    if is_dark { Color32::GOLD } else { Color32::from_rgb(180, 110, 0) }
                };
                ui.label(RichText::new(format!(
                    "⌨️ Keyboard HID: {} Terdaftar ({})",
                    hid_count,
                    if self.config.quarantine_new_hid_keyboard { "Zero-Trust Aktif" } else { "Karantina OFF" }
                )).color(hid_badge_color).strong());

                ui.separator();

                // USB Mass Storage Status
                let usb_lock_badge = if self.is_usb_blocked {
                    let col = if is_dark { Color32::from_rgb(255, 100, 100) } else { Color32::from_rgb(200, 30, 30) };
                    RichText::new("🔒 USB Storage: DIBLOKIR").color(col).strong()
                } else {
                    let col = if is_dark { Color32::from_rgb(100, 180, 255) } else { Color32::from_rgb(20, 100, 200) };
                    RichText::new("🔓 USB Storage: Terbuka").color(col)
                };
                ui.label(usb_lock_badge);

                ui.separator();

                // Quick toggle USB Block
                let toggle_txt = if self.is_usb_blocked { "Izinkan USB Drive" } else { "Blokir USB Drive (Cegah Flashdisk)" };
                if ui.small_button(toggle_txt).on_hover_text("Memblokir atau mengizinkan port USB membaca flashdisk (mencegah pencurian data & malware via USB)").clicked() {
                    let target_state = !self.is_usb_blocked;
                    match UsbMonitor::set_usb_storage_blocked(target_state) {
                        Ok(_) => {
                            self.is_usb_blocked = target_state;
                            self.status_text = if target_state {
                                "Port penyimpanan USB berhasil diblokir via Registry USBSTOR.".to_string()
                            } else {
                                "Port penyimpanan USB diizinkan kembali.".to_string()
                            };
                        }
                        Err(e) => {
                            self.status_text = format!("Error: {}", e);
                        }
                    }
                }
            });

            ui.add_space(3.0);

            // Row 2: Live Typing Telemetry Meter
            let (live_cpm, live_source, live_jitter) = {
                if let Ok(det) = self.detector.lock() {
                    det.live_telemetry()
                } else {
                    (0, InputSource::HardwareHid, 0.0)
                }
            };

            ui.horizontal(|ui| {
                ui.label(RichText::new("⚡ Telemetri Input:").size(12.0).strong());
                let cpm_color = if live_cpm >= 1800 {
                    Color32::from_rgb(255, 75, 75)
                } else if live_cpm >= 1200 {
                    Color32::GOLD
                } else {
                    ui.visuals().text_color()
                };
                ui.label(RichText::new(format!("Kecepatan: {} CPM", live_cpm)).color(cpm_color).size(12.0));
                ui.label(RichText::new(format!("| Jitter: {:.1} ms", live_jitter)).color(ui.visuals().weak_text_color()).size(12.0));
                ui.label(RichText::new(format!("| Sumber Terakhir: {}", live_source)).color(ui.visuals().weak_text_color()).size(12.0));
            });

            ui.add_space(4.0);
        });

        // Bottom Status Panel
        egui::TopBottomPanel::bottom("bottom_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&self.status_text).size(12.0).color(ui.visuals().weak_text_color()));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new("Kernel Hook: WH_KEYBOARD_LL | Keystroke Firewall: Aktif").size(11.0).color(ui.visuals().weak_text_color()));
                });
            });
        });

        // Interactive Guide Window
        if self.show_info_guide {
            egui::Window::new("ℹ️ Cara Kerja Deteksi & Pencegahan (Panduan Keamanan v1.1.0)")
                .collapsible(false)
                .resizable(true)
                .default_size(Vec2::new(560.0, 420.0))
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ScrollArea::vertical().show(ui, |ui| {
                        ui.heading("Arsitektur Pertahanan KeySentinel v1.1.0");
                        ui.add_space(4.0);
                        ui.label("Pembaruan v1.1.0 memperkenalkan pertahanan preventif aktif dan algoritma cerdas anti false-positive:");

                        ui.add_space(10.0);
                        ui.group(|ui| {
                            ui.label(RichText::new("1. 🧠 Eliminasi False Positive (Tahan Tombol & Jitter Analysis)").strong().size(14.0));
                            ui.label(
                                "• Di Windows, menahan tombol (seperti Backspace, Spasi, atau Panah) memicu auto-repeat ~30 ketikan/detik (900-1350 CPM). Pada v1.0.0 hal ini menimbulkan peringatan palsu.\n\
                                 • KeySentinel v1.1.0 melacak status 'held keys' (tombol sedang ditekan). Ketikan auto-repeat diabaikan dari burst counter!\n\
                                 • Mengukur Jitter Waktu (Variansi Biologis): Manusia mengetik secepat apa pun selalu memiliki variasi interval (jitter tinggi >15ms). Script BadUSB / Rubber Ducky memiliki interval mikrodetik super-teratur (jitter sangat rendah <8ms)."
                            );
                        });

                        ui.add_space(8.0);
                        ui.group(|ui| {
                            ui.label(RichText::new("2. 🛡️ Active Keystroke Firewall (Blokir Real-time)").strong().size(14.0));
                            ui.label(
                                "• Bukan sekadar mencatat log! Saat serangan injeksi terdeteksi (atau pemicu Win+R kilat), KeySentinel langsung menjatuhkan/menelan tombol (return 1 pada low-level hook).\n\
                                 • Perintah attacker (seperti 'powershell Invoke-WebRequest...') diblokir di tingkat hook kernel sebelum sampai ke aplikasi Windows mana pun.\n\
                                 • Input keyboard dikarantina sementara selama 15 detik untuk menghentikan payload sepenuhnya."
                            );
                        });

                        ui.add_space(8.0);
                        ui.group(|ui| {
                            ui.label(RichText::new("3. 🔌 Zero-Trust HID Keyboard Guard").strong().size(14.0));
                            ui.label(
                                "• BadUSB modern (Rubber Ducky, Flipper Zero BadUSB, Bash Bunny) TIDAK menancap sebagai flashdisk, melainkan sebagai keyboard USB palsu!\n\
                                 • KeySentinel mencatat keyboard tepercaya. Saat ada keyboard USB baru ditancapkan ke PC, input otomatis dikarantina selama 15 detik.\n\
                                 • Skrip jahat yang langsung mengetik dalam 1 detik akan terblokir sejak karakter ke-0! Pengguna asli dapat membuka blokir dengan mengklik 'Percayai Keyboard Ini' menggunakan mouse."
                            );
                        });

                        ui.add_space(12.0);
                        if ui.button("Tutup Panduan").clicked() {
                            self.show_info_guide = false;
                        }
                    });
                });
        }

        // Settings Window
        if self.show_settings {
            egui::Window::new("⚙️ Pengaturan KeySentinel")
                .collapsible(false)
                .resizable(false)
                .default_size(Vec2::new(520.0, 380.0))
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.heading("Konfigurasi Pertahanan Fisik & Keystroke Firewall");
                    ui.label("Sesuaikan kebijakan proteksi proaktif terhadap serangan BadUSB dan keylogger.");

                    ui.add_space(8.0);

                    // Setting 1: Active Keystroke Firewall
                    if ui.checkbox(&mut self.config.block_malicious_input, "🛡️ Blokir Otomatis Ketikan BadUSB / Injeksi Kilat (Active Keystroke Firewall)").changed() {
                        self.firewall.policy.block_malicious_input.store(self.config.block_malicious_input, Ordering::Relaxed);
                        self.config.save();
                    }
                    ui.label(RichText::new("Menelan dan memblokir langsung keystroke dari injeksi otomatis sebelum mencapai terminal/Run/PowerShell.").size(11.0).color(ui.visuals().weak_text_color()));

                    ui.add_space(6.0);

                    // Setting 2: Zero-Trust HID Guard
                    if ui.checkbox(&mut self.config.quarantine_new_hid_keyboard, "🔌 Karantina Otomatis Saat Ada Keyboard USB Baru Dicolok (Zero-Trust HID Guard)").changed() {
                        self.hid_guard.set_quarantine_enabled(self.config.quarantine_new_hid_keyboard);
                        self.config.save();
                    }
                    ui.label(RichText::new("Mengunci input selama 15 detik saat keyboard USB baru ditancapkan. Menghentikan BadUSB sejak karakter pertama.").size(11.0).color(ui.visuals().weak_text_color()));

                    ui.add_space(6.0);

                    // Setting 3: Shell Payload Guard (Win+R)
                    if ui.checkbox(&mut self.config.block_win_r_rapid, "🚫 Blokir Kombinasi Kilat Win+R (Shell Payload Guard)").changed() {
                        self.config.save();
                    }
                    ui.label(RichText::new("Mendeteksi dan memblokir karakter kilat (<25ms) yang langsung diketik sesaat setelah tombol Win+R ditekan.").size(11.0).color(ui.visuals().weak_text_color()));

                    ui.add_space(6.0);

                    // Setting 4: Software Synthetic Keystroke Blocker
                    if ui.checkbox(&mut self.config.block_software_sendinput, "🤖 Blokir Ketikan Software Sintetis (SendInput / Macro / Remote)").changed() {
                        self.firewall.policy.block_software_sendinput.store(self.config.block_software_sendinput, Ordering::Relaxed);
                        self.config.save();
                    }
                    ui.label(RichText::new("Memblokir ketikan buatan yang disuntikkan software lewat SendInput API (berguna jika menduga ada remote spyware).").size(11.0).color(ui.visuals().weak_text_color()));

                    ui.add_space(6.0);

                    // Setting 5: Auto-Lock Workstation
                    if ui.checkbox(&mut self.config.auto_lock_on_badusb, "🔒 Kunci Layar Windows Otomatis Saat Serangan Kritis").changed() {
                        if let Ok(mut det) = self.detector.lock() {
                            det.set_auto_lock(self.config.auto_lock_on_badusb);
                        }
                        self.config.save();
                    }
                    ui.label(RichText::new("Otomatis mengunci layar workstation jika terjadi injeksi CPM ekstrem untuk menggagalkan skrip penyerang.").size(11.0).color(ui.visuals().weak_text_color()));

                    ui.add_space(6.0);

                    // Setting 6: System Auto Start on Boot
                    if ui.checkbox(&mut self.config.autostart_on_boot, "🚀 Jalankan Otomatis Saat Windows Menyala (System Auto Start)").changed() {
                        let res = autostart::set_autostart(self.config.autostart_on_boot);
                        if let Err(e) = res {
                            self.status_text = format!("Gagal mengubah autostart: {}", e);
                            self.config.autostart_on_boot = autostart::is_autostart_enabled();
                        } else {
                            self.status_text = if self.config.autostart_on_boot {
                                "KeySentinel didaftarkan untuk jalan otomatis saat Windows menyala.".to_string()
                            } else {
                                "KeySentinel dihapus dari startup Windows.".to_string()
                            };
                        }
                        self.config.save();
                    }
                    ui.label(RichText::new("Mendaftarkan KeySentinel ke registry Run pengguna agar perlindungan selalu siaga sejak boot.").size(11.0).color(ui.visuals().weak_text_color()));

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);

                    // Theme selector
                    ui.horizontal(|ui| {
                        ui.label("Tema Tampilan:");
                        let prev = self.config.theme.clone();
                        egui::ComboBox::from_label("")
                            .selected_text(match self.config.theme.as_str() {
                                "dark" => "🌙 Mode Gelap",
                                "light" => "☀️ Mode Terang",
                                _ => "🖥️ Ikuti Sistem",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.config.theme, "system".to_string(), "🖥️ Ikuti Sistem");
                                ui.selectable_value(&mut self.config.theme, "dark".to_string(), "🌙 Mode Gelap");
                                ui.selectable_value(&mut self.config.theme, "light".to_string(), "☀️ Mode Terang");
                            });
                        if self.config.theme != prev {
                            self.apply_theme(ctx);
                            self.config.save();
                        }
                    });

                    ui.add_space(8.0);
                    if ui.button("Tutup").clicked() {
                        self.show_settings = false;
                    }
                });
        }

        // Side Panel: Threat Log
        egui::SidePanel::right("side_events")
            .min_width(320.0)
            .default_width(360.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.heading(RichText::new("📜 Log Serangan & Aktivitas").size(16.0).strong());
                ui.separator();

                let events_snapshot = {
                    if let Ok(evts) = self.events.lock() {
                        evts.clone()
                    } else {
                        Vec::new()
                    }
                };

                if events_snapshot.is_empty() {
                    ui.add_space(20.0);
                    ui.label("Belum ada aktivitas mencurigakan atau drive baru terdeteksi.");
                } else {
                    ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                        for ev in events_snapshot {
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    let badge_color = match ev.severity {
                                        EventSeverity::Critical => if is_dark { Color32::from_rgb(255, 75, 75) } else { Color32::from_rgb(200, 20, 20) },
                                        EventSeverity::Warning => if is_dark { Color32::GOLD } else { Color32::from_rgb(180, 110, 0) },
                                        EventSeverity::Info => if is_dark { Color32::from_rgb(100, 180, 255) } else { Color32::from_rgb(20, 100, 200) },
                                    };
                                    ui.label(RichText::new(&ev.title).strong().color(badge_color));
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.label(RichText::new(&ev.timestamp).size(11.0).color(ui.visuals().weak_text_color()));
                                    });
                                });
                                ui.label(RichText::new(&ev.description).size(12.0));
                            });
                            ui.add_space(4.0);
                        }
                    });
                }
            });

        // Central Panel
        egui::CentralPanel::default().show(ctx, |ui| {
            // High-visibility Alert Bar if Keyboard Input is Quarantined
            let (is_quarantined, rem_secs, reason) = self.firewall.get_quarantine_info();
            if is_quarantined {
                ui.group(|ui| {
                    let alert_bg = if is_dark {
                        Color32::from_rgb(120, 20, 20)
                    } else {
                        Color32::from_rgb(255, 220, 220)
                    };
                    let alert_text_color = if is_dark {
                        Color32::from_rgb(255, 120, 120)
                    } else {
                        Color32::from_rgb(180, 0, 0)
                    };

                    ui.painter().rect_filled(ui.available_rect_before_wrap(), 4.0, alert_bg);

                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("🚨 KARANTINA INPUT KEYBOARD AKTIF!").size(15.0).strong().color(alert_text_color));
                            ui.label(RichText::new(format!("(Sisa Waktu: {} detik)", rem_secs)).strong());
                        });
                        ui.label(RichText::new(format!("Alasan: {}", reason)).size(13.0));
                        ui.label(RichText::new("Semua keystroke saat ini ditelan/diblokir oleh Keystroke Firewall demi melindungi sistem.").size(12.0));

                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if ui.button(RichText::new("🔓 Buka Karantina Keyboard (Klik dengan Mouse)").strong()).clicked() {
                                self.firewall.unblock();
                                self.status_text = "Karantina keyboard dibuka manual oleh pengguna via mouse.".to_string();
                            }

                            if ui.button(RichText::new("✅ Percayai Keyboard Baru Ini").strong()).clicked() {
                                self.hid_guard.trust_all_current();
                                self.firewall.unblock();
                                self.status_text = "Keyboard baru ditambahkan ke daftar tepercaya dan karantina diakhiri.".to_string();
                            }
                        });
                    });
                });
                ui.add_space(10.0);
            }

            ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                // Section 1: USB Flashdrive & Removable Storage Inspector
                ui.heading(RichText::new("💾 Pemindai Drive USB & Payload Tersembunyi").size(16.0));
                ui.label("Memeriksa drive yang dicolok secara fisik untuk mendeteksi berkas autorun, shortcut LNK exploit, dan skrip berbahaya.");
                ui.add_space(4.0);

                if self.removable_drives.is_empty() {
                    ui.group(|ui| {
                        ui.label(RichText::new("ℹ️ Tidak ada drive USB/Removable yang terpasang saat ini.").color(ui.visuals().weak_text_color()));
                    });
                } else {
                    for d in &self.removable_drives {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("Drive {}: [{}]", d.letter, d.volume_name)).strong().size(14.0));
                                ui.label(format!("(FS: {} | Kapasitas: {} MB / Bebas: {} MB)", d.file_system, d.total_space_mb, d.free_space_mb));
                            });

                            if d.suspicious_findings.is_empty() {
                                let col = if is_dark { Color32::from_rgb(60, 210, 70) } else { Color32::from_rgb(0, 140, 30) };
                                ui.label(RichText::new("✅ Bersih: Tidak ditemukan autorun.inf atau payload executable di root drive.").color(col));
                            } else {
                                for f in &d.suspicious_findings {
                                    let col = if is_dark { Color32::from_rgb(255, 75, 75) } else { Color32::from_rgb(200, 20, 20) };
                                    ui.label(RichText::new(format!("• {}", f)).color(col).strong());
                                }
                            }
                        });
                        ui.add_space(4.0);
                    }
                }

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);

                // Section 2: Potential Keylogger & Process Hook Inspector
                ui.heading(RichText::new("🕵️ Deteksi Keylogger & Proses Mencurigakan").size(16.0));
                ui.label("Memeriksa proses sistem yang berjalan dari direktori tidak lazim (Temp/AppData/Downloads) atau memiliki nama khas stealer.");
                ui.add_space(4.0);

                if self.suspicious_hooks.is_empty() {
                    ui.group(|ui| {
                        let col = if is_dark { Color32::from_rgb(60, 210, 70) } else { Color32::from_rgb(0, 140, 30) };
                        ui.label(RichText::new("✅ Sistem Bersih: Tidak ditemukan proses latar belakang yang dicurigai sebagai keylogger.").color(col));
                    });
                } else {
                    egui::Grid::new("keylog_table").striped(true).min_col_width(80.0).show(ui, |ui| {
                        ui.label(RichText::new("Tingkat Risiko").strong());
                        ui.label(RichText::new("Nama Proses").strong());
                        ui.label(RichText::new("PID").strong());
                        ui.label(RichText::new("Kategori").strong());
                        ui.label(RichText::new("Alasan / Temuan").strong());
                        ui.end_row();

                        for proc in &self.suspicious_hooks {
                            let badge_color = if proc.suspicious_score >= 60 {
                                if is_dark { Color32::from_rgb(255, 75, 75) } else { Color32::from_rgb(200, 20, 20) }
                            } else {
                                if is_dark { Color32::GOLD } else { Color32::from_rgb(180, 110, 0) }
                            };
                            ui.label(RichText::new(format!("Skor: {}", proc.suspicious_score)).color(badge_color).strong());
                            ui.label(RichText::new(&proc.process_name).strong());
                            ui.label(format!("{}", proc.process_id));
                            ui.label(&proc.hook_type);
                            ui.label(&proc.description);
                            ui.end_row();
                        }
                    });
                }
            });
        });
    }
}
