use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText, ScrollArea, Vec2};

use crate::anti_keylogger::{HookDetectionInfo, KeyloggerDetector};
use crate::badusb::{EventSeverity, UsbAttackEvent};
use crate::usb_monitor::{UsbDriveInfo, UsbMonitor};

#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
pub struct AppConfig {
    pub auto_lock_on_badusb: bool,
    pub usb_storage_lock: bool,
    pub theme: String, // "system", "dark", "light"
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
        if let Ok(content) = fs::read_to_string(path) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Self {
                auto_lock_on_badusb: true,
                usb_storage_lock: false,
                theme: "system".to_string(),
            }
        }
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
    events: Arc<Mutex<Vec<UsbAttackEvent>>>,

    // State
    removable_drives: Vec<UsbDriveInfo>,
    suspicious_hooks: Vec<HookDetectionInfo>,
    is_usb_blocked: bool,
    status_text: String,
    last_scan: Instant,
    show_settings: bool,

    system_visuals: egui::Visuals,
}

impl KeySentinelApp {
    pub fn new(cc: &eframe::CreationContext<'_>, detector: Arc<Mutex<KeyloggerDetector>>, events: Arc<Mutex<Vec<UsbAttackEvent>>>) -> Self {
        let config = AppConfig::load();
        let system_visuals = cc.egui_ctx.style().visuals.clone();

        match config.theme.as_str() {
            "dark" => cc.egui_ctx.set_visuals(egui::Visuals::dark()),
            "light" => cc.egui_ctx.set_visuals(egui::Visuals::light()),
            _ => cc.egui_ctx.set_visuals(system_visuals.clone()),
        }

        let is_usb_blocked = UsbMonitor::is_usb_storage_blocked();
        let mut usb_monitor = UsbMonitor::new();
        let (_, drives) = usb_monitor.check_new_insertions();

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
            events,
            removable_drives: drives,
            suspicious_hooks: initial_hooks,
            is_usb_blocked,
            status_text: "KeySentinel aktif. Memantau BadUSB, Injeksi Keystroke & USB Drive secara real-time.".to_string(),
            last_scan: Instant::now(),
            show_settings: false,
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
        let (new_drives, all_drives) = self.usb_monitor.check_new_insertions();
        self.removable_drives = all_drives;

        // If new drives found, log event
        for d in new_drives {
            if let Ok(mut evts) = self.events.lock() {
                let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                let has_threat = !d.suspicious_findings.is_empty();
                evts.insert(0, UsbAttackEvent {
                    timestamp: ts,
                    title: format!("💾 USB Terpasang ({})", d.letter),
                    description: format!(
                        "Drive USB '{}' terdeteksi. Temuan: {}",
                        d.volume_name,
                        if has_threat { d.suspicious_findings.join(", ") } else { "Tidak ada payload mencurigakan di root".to_string() }
                    ),
                    severity: if has_threat { EventSeverity::Critical } else { EventSeverity::Info },
                });
            }
        }

        if let Ok(det) = self.detector.lock() {
            self.suspicious_hooks = det.scan_processes_for_keyloggers();
        }

        self.is_usb_blocked = UsbMonitor::is_usb_storage_blocked();
        self.last_scan = Instant::now();
        self.status_text = format!(
            "Pembaruan selesai. {} drive USB terdeteksi | {} proses diperiksa.",
            self.removable_drives.len(),
            self.suspicious_hooks.len()
        );
    }
}

impl eframe::App for KeySentinelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_theme(ctx);
        let is_dark = ctx.style().visuals.dark_mode;

        // Auto-refresh scan every 3 seconds
        if self.last_scan.elapsed() >= Duration::from_secs(3) {
            self.refresh_all();
        }

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
                ui.label(RichText::new("v1.0.0 | Anti-Keylogger, BadUSB & Physical Attack Defense").color(ui.visuals().weak_text_color()));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⚙️ Pengaturan").clicked() {
                        self.show_settings = !self.show_settings;
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

            // Protection Status Dashboard
            ui.horizontal(|ui| {
                // BadUSB Interceptor Status
                let auto_lock_badge = if self.config.auto_lock_on_badusb {
                    let col = if is_dark { Color32::from_rgb(80, 220, 100) } else { Color32::from_rgb(0, 140, 30) };
                    RichText::new("🟢 BadUSB Interceptor: AKTIF (Auto-Lock)").color(col).strong()
                } else {
                    let col = if is_dark { Color32::GOLD } else { Color32::from_rgb(180, 110, 0) };
                    RichText::new("🟡 BadUSB Interceptor: Hanya Peringatan").color(col)
                };
                ui.label(auto_lock_badge);

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
                let toggle_txt = if self.is_usb_blocked { "Izinkan USB Drive" } else { "Blokir USB Drive (Cegah Copot/Colok)" };
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
            ui.add_space(6.0);
        });

        // Bottom Status Panel
        egui::TopBottomPanel::bottom("bottom_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&self.status_text).size(12.0).color(ui.visuals().weak_text_color()));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new("Hook Kernel: Low-Level WH_KEYBOARD_LL").size(11.0).color(ui.visuals().weak_text_color()));
                });
            });
        });

        // Settings Window
        if self.show_settings {
            egui::Window::new("⚙️ Pengaturan KeySentinel")
                .collapsible(false)
                .resizable(false)
                .default_size(Vec2::new(450.0, 260.0))
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.heading("Konfigurasi Proteksi Fisik & Keylogger");
                    ui.label("Pertahanan terhadap serangan fisik colok USB kilat (BadUSB / Rubber Ducky) dan malware pengintai tombol keyboard.");

                    ui.add_space(8.0);
                    if ui.checkbox(&mut self.config.auto_lock_on_badusb, "Otomatis Kunci Komputer Saat Terdeteksi BadUSB / Injeksi Kilat").changed() {
                        if let Ok(mut det) = self.detector.lock() {
                            det.set_auto_lock(self.config.auto_lock_on_badusb);
                        }
                        self.config.save();
                    }
                    ui.label(RichText::new("Jika kecepatan input keyboard melonjak drastis (>1800 CPM / injeksi mesin), layar otomatis terkunci dalam <1 detik sehingga skrip attacker langsung gagal.").size(11.0).color(ui.visuals().weak_text_color()));

                    ui.add_space(10.0);
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

                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(6.0);
                    if ui.button("Tutup").clicked() {
                        self.show_settings = false;
                    }
                });
        }

        // Side Panel: Real-time Threat & Insertion Audit Log
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

        // Central Panel: Removable Drives Inspection & Suspicious Process Hooks
        egui::CentralPanel::default().show(ctx, |ui| {
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
                                ui.label(format!("(FS: {})", d.file_system));
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
