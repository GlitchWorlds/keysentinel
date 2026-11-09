# 🛡️ KeySentinel

**KeySentinel** is an enterprise-grade, lightweight, real-time native Windows endpoint security suite designed to neutralize **BadUSB hardware keystroke injection**, **physical USB drop attacks**, and **stealth keyloggers**.

KeySentinel combines an **Active Keystroke Firewall** with a **Multi-Signal Smart Detection Engine** and **Zero-Trust HID Keyboard Guard**, stopping automated USB payloads (such as USB Rubber Ducky, Flipper Zero BadUSB, Bash Bunny, or Digispark HID emulators) dead in their tracks before a single malicious character can reach a shell or application.

---

## ⚡ What's New in v1.1.0

### 1. 🛡️ Active Keystroke Firewall (`WH_KEYBOARD_LL` Real-Time Blocking)
- **Active In-Hook Interception**: Unlike passive tools that merely log alerts, KeySentinel actively swallows and drops (`return 1`) malicious keystrokes at the Windows kernel hook level before they reach Run, CMD, PowerShell, or any active window.
- **Automated Quarantine**: When an automated burst or Win+R payload is detected, keyboard input is instantly quarantined for 15 seconds.
- **Fail-Safe Mouse Unblock**: A prominent GUI alert bar allows users to immediately restore keyboard input with a single mouse click (`🔓 Buka Karantina Keyboard`).
- **Live Counter**: Displays real-time counts of swallowed and blocked keystrokes.

### 2. 🧠 Multi-Signal Smart Detection Engine (Zero Human False Positives)
- **Typematic Auto-Repeat Elimination**: Tracks `held_keys` state. Holding down `Backspace`, `Space`, `Arrow`, or `Delete` triggers ~30 repeated `WM_KEYDOWN` events/sec in Windows; v1.1.0 recognizes held keys and never counts them as attack bursts!
- **Biological Jitter Analysis ($\sigma_{\Delta t}$)**: Measures standard deviation of intervals between keystrokes. Machine scripts (Rubber Ducky) execute with ultra-uniform clockwork timing (jitter < 8.0 ms), while human typing possesses natural biological variance (jitter > 15 ms).
- **Win+R Shell Payload Guard**: Detects rapid alphanumeric characters (< 25 ms interval) typed within milliseconds of `Win + R` (the classic `GUI r -> powershell` signature).
- **Input Source Attribution**: Distinguishes between `Hardware USB HID` devices, `Software SendInput` synthetic macros, and `Lower-Integrity Injected` events via `KBDLLHOOKSTRUCT` flags.
- **Target Process Logging**: Captures foreground window titles and process names upon threat detection.
- **Debounce Fix**: Eliminates duplicate event cards with a category-based 3-second cooldown and newest-event inspection.

### 3. 🔌 Zero-Trust HID Keyboard Guard
- **HID vs Flashdrive Defense**: BadUSB devices masquerade as USB HID Keyboards rather than storage drives.
- **Raw Input Enumeration**: Uses Win32 Raw Input (`GetRawInputDeviceList`, `GetRawInputDeviceInfoW`) to track attached keyboard hardware (`VID_xxxx&PID_xxxx`).
- **Plug-and-Block Quarantine**: Automatically locks input for 15 seconds when a brand-new keyboard device is plugged in, neutralizing 1-second auto-run payload scripts before they can type character 0.
- **Trust Authorization**: Users can verify and whitelist newly connected hardware with mouse approval (`✅ Percayai Keyboard Baru Ini`).

### 4. 🚀 Windows System Auto-Start (`HKCU\...\Run`)
- Integrated registry toggle in Settings to ensure endpoint protection is active from the moment Windows boots.
- Runs without any flashing CMD windows (`CREATE_NO_WINDOW`).

### 5. 🌓 Adaptive High-Contrast Interface
- **Native Rust & egui GUI**: Tiny memory footprint (~16 MB RAM) and near-zero CPU usage.
- **Live Telemetry Meter**: Displays real-time CPM, timing jitter, and input source.
- **100% Adaptive Themes**: Clean contrast in Windows Light Mode and Dark Mode.
- **Security Guide Tab**: Built-in interactive Indonesian documentation explaining BadUSB vectors and preventive mechanics.

---

## 🚀 Installation & Running

### Download Pre-built Binary
Download the latest release zip (`keysentinel-windows-x64.zip`) from the [GitHub Releases](https://github.com/GlitchWorlds/keysentinel/releases) page. Extract and launch `keysentinel.exe`.

### Build from Source

#### Prerequisites
- Rust 1.75+ (`stable-x86_64-pc-windows-gnu` or `msvc`)
- Cargo

#### Build
```bash
git clone https://github.com/GlitchWorlds/keysentinel.git
cd keysentinel
cargo build --release
```
The optimized binary will be located at `target/release/keysentinel.exe`.

---

## 🛡️ Architecture & Security Model

```
                         ┌────────────────────────┐
                         │  Windows Kernel / OS   │
                         └───────────┬────────────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          ▼                          ▼                          ▼
┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
│  WH_KEYBOARD_LL   │      │ Win32 Raw Input   │      │  USBSTOR Registry │
│ Low-Level Hook    │      │ HID Device Audit  │      │ & Removable Drives│
└─────────┬─────────┘      └─────────┬─────────┘      └─────────┬─────────┘
          │                          │                          │
          ▼                          ▼                          ▼
┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
│ Multi-Signal      │      │ Zero-Trust New    │      │ Autorun/LNK/VBS   │
│ Heuristics &      │      │ Hardware HID      │      │ Payload Scanner   │
│ Jitter Engine     │      │ Hotplug Guard     │      │                   │
└─────────┬─────────┘      └─────────┬─────────┘      └─────────┬─────────┘
          │                          │                          │
          └──────────────────────────┼──────────────────────────┘
                                     │
                                     ▼
                      ┌─────────────────────────────┐
                      │  Active Keystroke Firewall  │
                      │  • Drop / Swallow (ret 1)   │
                      │  • 15s Input Quarantine     │
                      │  • Sub-Second Auto-Lock     │
                      │  • Audit & Forensic Logging │
                      └─────────────────────────────┘
```

---

## ⚙️ Configuration Options

| Option | Default | Purpose |
| :--- | :---: | :--- |
| **Active Keystroke Firewall** | `Enabled` | Drops malicious keystrokes at the OS hook before apps receive them |
| **Zero-Trust HID Guard** | `Enabled` | Quarantines input for 15s upon new keyboard hotplug |
| **Win+R Payload Guard** | `Enabled` | Blocks rapid keystrokes immediately following Win+R |
| **Software SendInput Blocker** | `Disabled` | Blocks synthetic keystrokes injected by software scripts/remote tools |
| **Auto-Lock on Critical Attack** | `Enabled` | Locks Windows workstation on high-velocity attacks |
| **System Auto-Start** | `Configurable`| Automatically runs KeySentinel on Windows boot via Registry |

---

## 📄 License
MIT License. Free and open source for personal and enterprise workstation defense.
