# Camera Login Valid Checker v3.0 - Advanced Camera Scanner & Brute Force Tool

<div align="center">

![Visitors](https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2FW8SOJIB%2FW8CameraHackV3&label=Visitors&countColor=%23263759&style=flat)
![GitHub Views](https://komarev.com/ghpvc/?username=W8SOJIB&label=Profile%20Views&color=0e75b6&style=flat)
[![GitHub Stars](https://img.shields.io/github/stars/W8SOJIB/W8CameraHackV3?style=social)](https://github.com/W8SOJIB/W8CameraHackV3)
[![GitHub Forks](https://img.shields.io/github/forks/W8SOJIB/W8CameraHackV3?style=social)](https://github.com/W8SOJIB/W8CameraHackV3)

![Python Version](https://img.shields.io/badge/python-3.7%2B-blue?style=flat&logo=python)
![Termux Support](https://img.shields.io/badge/Termux-Compatible-green?style=flat&logo=android)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20Android-lightgrey?style=flat)
![License](https://img.shields.io/badge/license-MIT-green?style=flat)
![Countries](https://img.shields.io/badge/countries-44-brightgreen?style=flat)
![One Click](https://img.shields.io/badge/operation-one--click-orange?style=flat)

### 🎯 Real-Time Visitor Counter - See Who's Visiting! 👆

</div>
Advanced Python CLI network device scanner supporting 243+ countries across all 5 RIR regions (APNIC, RIPE, ARIN, LACNIC, AFRINIC). Auto-fetches IP ranges from any regional registry, detects IP Cameras, NVR/DVR, Routers, and other network devices with geolocation, and saves results to files. Includes Telegram integration for real-time alerts and result file sharing.

## 🆕 What's New in V3.0?

Upgrading from [V2](https://github.com/W8SOJIB/W8CameraHackV2)? Here's what's new:

**How to Run**
Run via the "Run Camera Scanner V3" workflow which executes python W8CameraHackV3.py.

**Main Menu (Options 1-13):**

1. **Random Camera Scan — select country, detect devices across 5 RIR regions**
2. **Login Check from Saved TXT File — brute-force credentials against found cameras**
3. **IP Range Scan — scan a specific CIDR/IP range manually**
4. **View All Valid Camera — display validated login results**
5. **Send Result File to Telegram — manually push any result file to Telegram**
6. **Merge & Deduplicate Result Files and CCTV Found Files**
7. **Password Analysis (Aggregator) — stats on cracked passwords**
8. **Credential Success Stats — per-credential success rates**
9. **Exit**
10. **Help & Feature Reference**
11. **NVR Channel Splitter — split multi-channel NVR streams**
12. **Extra Tools — RTSP Brute Force, Heatmap, QR Code, CVE checker, Diff, CSV export…**
13. **RTSP Path Tester & File Viewer — 5-item submenu (see below):**
# **Option 13 — RTSP Path Tester & File Viewer**
**Submenu with five modes, all with Telegram integration and result-file send:**

-	Mode	Description:
1. **Single	Test one camera manually; auto-probes all brand paths; Basic + Digest auth**
2. **Batch	Read cameras from ValidCamera file(s); comma/dash file selection; live progress bar; resume/save support**
3. **View	Inspect RTSP result files — live/dead counts + URL table**
4. **M3U	Build a VLC-ready .m3u playlist from RTSP_Tested.txt**
5. **Quick Re-Test	Re-ping every URL in RTSP_Tested.txt; mark dead entries, remove them, write RTSP_Dead.txt; sends updated files to Telegram**
- **After every operation the result file (RTSP_Tested.txt / RTSP_Tested.m3u / RTSP_Dead.txt) is sent automatically to Telegram.**


### 🔐 Login Validation Features

- ✅ **HIK Vision Camera Support** - ISAPI Digest Authentication
- ✅ **Dahua/Anjhua Camera Support** - HTTP API & RTSP validation
- ✅ **Multi-Threaded Brute Force** - Fast credential testing
- ✅ **Default Credentials Database** - Common admin passwords included

## Key Features

### 🌍 Country Support
- **243 Country Support across 5 RIR regions (APNIC, RIPE, ARIN, LACNIC, AFRINIC)**

- **Expanded Device Detection: Hikvision, Dahua/Anjhua, NVR, DVR, ONVIF, Axis, Foscam, Reolink, Amcrest, Uniview, Tiandy, XMeye, Router (MikroTik/TP-Link/RouterOS)**

- **Device Model Extraction: Parses HTTP Server header for device model info**

- **Telegram Integration: Scan start/stop notifications, result file sending after every operation, valid password alerts, emergency backup on crash; multi-bot/channel config supported**

- **Resume Scan: Saves progress to scan_progress.json; prompts to continue or start fresh**

- **RTSP Path Tester (Option 13): Manual single probe, batch from ValidCamera files, live progress bar, save/resume, Quick Re-Test (re-ping + dead removal), M3U export, Telegram auto-send**

- **Preferred Admin Injector: Plants a configured admin account on confirmed devices via ISAPI / Dahua CGI / generic CGI; saves to PreferredAdmin_Accounts.txt**

- **Memory Pressure Monitor: Auto-pauses scan when RAM ≥ 85 %, resumes below 70 %**

- **Duplicate Removal: Automatically removes duplicate IP entries from result files after scan**

- **IP Geolocation: Shows city, region, country, postal code, ISP**

- **Auto IP Range Fetch: Downloads latest allocations from any of the 5 RIR registries**

- **Multi-Threaded Scanning: Up to 300 concurrent threads (matching original proven engine)**

- **Advanced Login Validator: Brute-force with Digest/Basic authentication (Hikvision & Dahua); credential list from credentials.txt**

- **Emergency Backup: Saves progress on crash/exit via Telegram and scan_progress.json**

- **Console Overlap Fix: Uses ANSI escape codes for clean progress output**

- **Main Menu Loop: Returns to menu after each operation instead of exiting**

- **4G/5G Mobile Camera Finder: Built-in carrier CIDR ranges for 20+ countries**

- **ISP Diversity Reporter: Tracks ISP sightings across scan sessions**

- **Auto Dashboard: Live scan stats dashboard with CVE/config/RTSP counts**

- **CVE Checker: Checks detected devices against known vulnerability patterns**

- **Heatmap / QR / CSV export: Extra tools in Option 12 submenu**

- 🌐 **Auto-Fetch IP Ranges** - **Automatically downloads from 5 RIR regions (APNIC, RIPE, ARIN, LACNIC, AFRINIC) database if file missing**

**RIR Registry URLs:**
- **APNIC (Asia-Pacific)**: ftp.apnic.net
- **RIPE NCC (Europe/Middle East/Central Asia)**: ftp.ripe.net
- **ARIN (North America/Caribbean)**: ftp.arin.net
- **LACNIC (Latin America/Caribbean)**: ftp.lacnic.net
- **AFRINIC (Africa)**: ftp.afrinic.net


**Telegram Config Format**
```bash
{
  "bot_token": "",
  "chat_id": "",
  "enabled": false,
  "send_realtime": true,
  "send_summary": true
}
```


### 📹 Camera Detection & Validation
- 🔍 **Fast Camera Detection** - Ultra-fast parallel port scanning
- 🔐 **Login Credential Validation** - Automatically tests default credentials
- 📡 **Multi-Brand Support**:
  - **HIK Vision Cameras** - ISAPI Digest Authentication
  - **Anjhua-Dahua Technology Cameras** - HTTP API & RTSP validation
- ✅ **Valid Credentials Tracking** - Saves successful logins with full details

### 📊 Advanced Features
- 🌍 **Geographic Location** - Auto-detects Country, Region, City, Postal Code
- 📈 **Summary Statistics** - Camera type breakdown and counts
- 💾 **Live Save** - Results saved instantly as they're found
- 🗂️ **Organized Output** - Separate files for each country
- 📋 **View Valid Cameras** - Browse all cameras with valid credentials

### ⚡ Performance
- 🚀 **Multi-Threaded** - Up to 500 threads for maximum speed
- ⚡ **Ultra-Fast Scanning** - 0.15s timeout per port
- 🔄 **Parallel Processing** - Simultaneous detection and validation
- 💻 **Termux Compatible** - Works perfectly on Android

### 🎨 User Interface
- 🎭 **Hacker-Style UI** - Clean terminal interface
- 🌈 **Colorful Output** - Easy to read status messages
- 📱 **Termux Optimized** - Perfect mobile experience

## Download Camera Live View App

Anjhua-Dahua Live View
https://github.com/W8SOJIB/W8AppStore/raw/refs/heads/main/DMSS_1_99_623_222.apk

HIK Vision Camera Live View
https://play.google.com/store/apps/details?id=com.connect.enduser&hl=en

Download Our App Store.. https://github.com/W8SOJIB/W8AppStore/raw/refs/heads/main/W8AppStore.apk


## Installation

### Quick Install (Recommended)

#### For Termux (Android)

```bash
# Update packages
pkg update && pkg upgrade

# Install required packages
pkg install python git

# Clone repository
git clone https://github.com/W8SOJIB/W8CameraHackV3
cd W8CameraHackV3

# Install Python dependencies
pip install requests colorama urllib3
```

## Run Tool

```bash
python W8CameraHackV3.py
```
 

#### For Desktop (Windows/Linux/Mac)

```bash
# Clone the repository
git clone https://github.com/W8SOJIB/W8CameraHackV3
cd W8CameraHackV3

# Install dependencies
pip install requests colorama urllib3
```

### Manual Installation

#### For Termux (Android)

```bash
# Update packages
pkg update && pkg upgrade

# Install required packages
pkg install python git

# Clone repository
git clone https://github.com/W8SOJIB/W8CameraHackV3
cd W8CameraHackV3

# Install Python dependencies
pip install requests colorama urllib3

# Optional: For better colors (if colorama install fails, the script works without it)
pip install colorama
```

#### For Desktop (Windows/Linux/Mac)

```bash
# Clone repository
git clone https://github.com/W8SOJIB/W8CameraHackV3
cd W8CameraHackV3

# Install Python dependencies
pip install requests colorama urllib3
```

## Usage

Run the script:
```bash
python W8CameraHackV3.py
```

### Menu Options

1. **Random Camera Scan** - Phase 1: Quickly detect cameras and save to file (no login attempts)
2. **Login Check from Saved TXT File** - Phase 2: Read saved cameras and validate credentials
3. **IP Range Scan** - Manual IP range scanning with login validation
4. **View All Valid Camera** - Browse all cameras with valid credentials

### 🔄 Two-Phase Workflow (Recommended)

**Phase 1: Fast Detection**
```bash
1. Select option 1
2. Choose country (e.g., Bangladesh)
3. Script auto-fetches IP ranges from APNIC
4. Fast camera detection (saves to BD_CCTV_Found.txt)
```

**Phase 2: Login Validation**
```bash
1. Select option 2
2. Choose saved CCTV file (e.g., BD_CCTV_Found.txt)
3. Script tries login credentials on all found cameras
4. Valid logins saved to BDValidCamera.txt with geographic location
```

**View Results**
```bash
1. Select option 4
2. Choose valid camera file (e.g., BDValidCamera.txt)
3. View all cameras with valid credentials and location info
```

### 🎮 Scan Controls

During scanning, you can use:
- **Ctrl+C** - ⛔ Stop scan immediately (instant exit)
- **Ctrl+Z** - ⏸️ Pause/Resume scan (toggle on Linux/Mac/Termux)

## Output Files

### Phase 1 Output: Camera Detection
- `[COUNTRY_CODE]_IP.txt` - Contains IP ranges for selected country in CIDR notation (auto-generated from APNIC)
- `[COUNTRY_CODE]_CCTV_Found.txt` - All detected cameras with details (Live Save)
  - **Anjhua-Dahua Technology Cameras** (WEB SERVICE detection)
  - **HIK Vision Cameras** (login.asp detection)

### Phase 2 Output: Valid Credentials
- `[COUNTRY_CODE]ValidCamera.txt` - Cameras with valid login credentials (e.g., `BDValidCamera.txt`, `PKValidCamera.txt`)
  - Includes summary statistics at top
  - Full geographic location data
  - Username and password for each camera

### Output Format

#### CCTV Found File (Detection Only):
```
============================================================
Camera Type: Anjhua-Dahua Technology Camera
IP Address: 192.168.1.100
Port: 80
URL: http://192.168.1.100
Detection Time: 2025-10-01 14:30:45
============================================================
```

#### ValidCamera File (With Credentials):
```
============================================================
Valid Camera Count Summary
============================================================
Total Valid Camera Count: 22
Anjhua-Dahua: 15
HIK Vision: 7
============================================================

============================================================
Camera Type: HIK Vision Camera
IP Address: 192.168.1.100
Port: 80
Username: admin
Password: admin123
Geographic Location
Country: Bangladesh
Region/State: Dhaka
City: Dhaka
Postal Code: 1000
============================================================
```

## How It Works

### Phase 1: Fast Camera Detection
1. **Country Selection**: Choose from 44 countries in the Asia-Pacific region (APNIC)
2. **Auto-Fetch IP Ranges**: Automatically downloads IPv4 ranges from APNIC if file doesn't exist
3. **CIDR Parsing**: Converts custom CIDR notation (IP/count) to individual IP addresses
4. **Ultra-Fast Port Scanning**: Parallel scanning of ports 80, 8080, 443, 554, 37777, 8000
5. **Camera Detection**: Identifies cameras via HTTP response analysis
6. **Live Save**: Results saved immediately to `[COUNTRY]_CCTV_Found.txt`

### Phase 2: Login Validation
1. **Read Saved Cameras**: Parses CCTV Found files for camera details
2. **Multi-Threaded Brute Force**: Tests default credentials on all cameras
3. **Authentication**: Uses ISAPI Digest (Hikvision) or HTTP Digest (Dahua)
4. **Geographic Lookup**: Fetches location data using multiple geolocation APIs
5. **Valid Credentials Save**: Saves successful logins to `[COUNTRY]ValidCamera.txt`

### Performance Optimizations
- **Up to 500 threads** for maximum scanning speed
- **0.15s timeout** per port for ultra-fast detection
- **Parallel processing** for both detection and validation
- **Auto-detects CPU cores** and scales thread count accordingly

## Ports Scanned

- **Port 80** (HTTP) - Most common camera port
- **Port 8080** (HTTP Alternative)
- **Port 443** (HTTPS)
- **Port 554** (RTSP - Dahua)
- **Port 37777** (Dahua SDK)
- **Port 8000** (Alternative HTTP)

## Default Credentials Tested

The tool automatically tries these common credentials:
- `admin:admin123`
- `admin:admin1234`
- `admin:admin12345`
- `admin:admin1122`
- `admin:12345`
- `admin:123456`
- `admin:password`

## Notes

### Performance
- **Ultra-fast scanning**: 0.15s timeout per port for maximum speed
- **Auto-threading**: Automatically uses 10x CPU cores (up to 500 threads)
- **Live Save**: Results saved instantly with `file.flush()` for real-time updates

### Controls
- **Ctrl+C**: Stop scanning immediately
- **Pause/Resume**: Not available (too fast for pause functionality)

### Compatibility
- ✅ **Termux Compatible** - Works perfectly on Android
- ✅ **Windows/Linux/Mac** - Full cross-platform support
- ✅ **Fallback Colors** - Works even without colorama

### Features
- **Auto-Fetch IP Ranges**: Downloads from APNIC automatically if file missing
- **Multiple Geolocation Services**: Falls back if primary service fails
- **Smart Detection**: Only saves confirmed camera types (no "Unknown Camera")
- **Summary Statistics**: Shows camera type breakdown in output files

## Legal Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning networks you don't own.

## Credits

<div align="center">

### 👨‍💻 Developed by: W8Team/W8SOJIB

[![GitHub](https://img.shields.io/badge/GitHub-W8SOJIB-181717?style=for-the-badge&logo=github)](https://github.com/W8SOJIB)
[![Profile Views](https://komarev.com/ghpvc/?username=W8SOJIB&label=Profile%20Views&color=blueviolet&style=for-the-badge)](https://github.com/W8SOJIB)

**Team:** W8Team  
**Contact:** [GitHub Profile](https://github.com/W8SOJIB)

</div>

### 📊 Repository Stats

![Repo Visitors](https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2FW8SOJIB%2FW8CameraHackV3&labelColor=%23697689&countColor=%23ff8a65&style=plastic&labelStyle=upper)
![GitHub code size](https://img.shields.io/github/languages/code-size/W8SOJIB/W8CameraHackV3?style=plastic)
![GitHub repo size](https://img.shields.io/github/repo-size/W8SOJIB/W8CameraHackV3?style=plastic)

### Version History
- 🆕 **V3.0** - Camera Login Valid Checker (Two-Phase Workflow, Credential Validation, Geographic Location)
- 📌 **[V2](https://github.com/W8SOJIB/W8CameraHackV2)** - Multi-Country Scanner (44 Countries, One-Click Operation)
- 📌 **[V1](https://github.com/W8SOJIB/W8CameraHackV1)** - Bangladesh Only Scanner (Legacy)

### What's Different from V2?

| Feature | V2 | V3.0 |
|---------|----|-----|
| Camera Detection | ✅ | ✅ |
| Login Validation | ❌ | ✅ |
| Geographic Location | ❌ | ✅ |
| Valid Credentials Save | ❌ | ✅ |
| Two-Phase Workflow | ❌ | ✅ |
| Auto-Fetch IP Ranges | ✅ | ✅ |
| View Valid Cameras | ❌ | ✅ |
| Summary Statistics | ❌ | ✅ |

### Original Components
- 📡 All ASN Collector (IP Range Fetcher)
- 📹 W8IPCameraHK V4 (Camera Scanner)
- 🔧 Combined & Optimized by W8SOJIB for Termux Support
- 🌍 Enhanced V2: Multi-Country Support + Auto-Scan
- 🔐 Enhanced V3: Login Validation + Geographic Location + Valid Credentials Tracking

---

<div align="center">

**⭐ If you like this project, please give it a star! ⭐**

Made with ❤️ by [W8Team/W8SOJIB](https://github.com/W8SOJIB)

</div>




