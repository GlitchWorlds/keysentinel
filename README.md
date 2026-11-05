# 🛡️ KeySentinel

**KeySentinel** is a lightweight, real-time native Windows endpoint defense tool designed to neutralize **BadUSB hardware injection**, **physical USB drop attacks**, and **stealth keyloggers**.

Inspired by physical social engineering tactics where attackers plug in automated USB payloads (such as USB Rubber Ducky, Bash Bunny, or malicious flash drives disguised as routine office devices), KeySentinel acts as an active digital tripwire.

---

## ⚡ Core Capabilities

### 1. ⚡ BadUSB & Keystroke Injection Interceptor (Rubber Ducky Defense)
- **High-Velocity Keystroke Detection**: Monitors keyboard input rates using a sliding-window heuristic. Automated HID injection attacks typically type commands at inhuman speeds (>1,800 Characters Per Minute / 30+ keys per second).
- **Sub-Second Auto-Lockdown**: Instantly triggers Windows `LockWorkStation()` the exact millisecond an automated keystroke burst is detected, cutting off the attacker's script and preventing unauthorized shell/PowerShell access.

### 2. 💾 Physical USB Drive Monitoring & Payload Inspection
- **Hotplug Event Detection**: Listens for removable media insertion events in real time.
- **Root Payload Inspection**: Automatically audits newly mounted drives for:
  - Malicious `autorun.inf` files configured with auto-execution directives.
  - Suspicious `.lnk` shortcut files (CVE LNK exploits).
  - Rogue `.vbs`, `.js`, `.hta`, `.bat`, `.cmd`, `.ps1` terminal scripts.
  - Executable binaries (`.exe`, `.scr`, `.pif`) sitting in the drive root.
- **Instant USB Mass Storage Lockdown**: One-click system toggle to disable or re-enable USB mass storage driver (`USBSTOR`) via Windows Registry.

### 3. 🕵️ Stealth Keylogger & Process Hook Inspector
- **Process Memory & Path Heuristics**: Identifies background processes executing out of non-standard locations (`\Temp\`, `\AppData\Local\Temp\`, `\Downloads\`).
- **Signature & Behavior Scoring**: Scores running processes for keylogger, grabber, and spyware indicators.

### 4. 🌓 Adaptive High-Contrast Interface
- **Native GUI built with Rust & egui**: Feather-light memory footprint (~15 MB RAM) with near-zero CPU usage.
- **Auto Theme Switching**: Seamlessly supports Windows Light Mode and Dark Mode with dynamic, high-contrast semantic typography.

---

## 🚀 Installation & Running

### Download Pre-built Binary
Download the latest release zip (`keysentinel-windows-x64.zip`) from the [Releases](https://github.com/GlitchWorlds/keysentinel/releases) tab. Extract and launch `keysentinel.exe`.

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
The optimized executable will be located at `target/release/keysentinel.exe`.

---

## 🛡️ Architecture & Security Model

```
                    ┌────────────────────────┐
                    │ Windows Kernel / OS    │
                    └───────────┬────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ WH_KEYBOARD_LL   │  │ Removable Drive  │  │ Process Audit &  │
│ Low-Level Hook   │  │ Hotplug Watcher  │  │ Hook Heuristics  │
└─────────┬────────┘  └─────────┬────────┘  └─────────┬────────┘
          │                     │                     │
          ▼                     ▼                     ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ Sliding-Window   │  │ Autorun/LNK/VBS  │  │ Temp/AppData     │
│ Burst Analyzer   │  │ Payload Scanner  │  │ Execution Hunter │
└─────────┬────────┘  └─────────┬────────┘  └─────────┬────────┘
          │                     │                     │
          └─────────────────────┼─────────────────────┘
                                │
                                ▼
                   ┌────────────────────────┐
                   │  Sub-Second Auto-Lock  │
                   │  & Incident Event Log  │
                   └────────────────────────┘
```

---

## 📄 License
MIT License. Free and open source for personal and enterprise workstation hardening.
