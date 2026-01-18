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

A powerful **two-phase camera scanner and login validator** that supports **44 countries** in the Asia-Pacific region (APNIC). Now with **automatic login credential validation** and geographic location tracking!

## 🆕 What's New in V3.0?

Upgrading from [V2](https://github.com/W8SOJIB/W8CameraHackV2)? Here's what's new:

### ⚡ Major New Features

- ✅ **Two-Phase Workflow** - Fast Detection → Login Validation
- ✅ **Automatic Login Brute Force** - Validates credentials automatically
- ✅ **Geographic Location Tracking** - Shows Country, Region, City, Postal Code
- ✅ **ValidCamera.txt Output** - Saves valid credentials with location data
- ✅ **View All Valid Cameras** - Browse all valid logins
- ✅ **Auto-Fetch IP Ranges** - Automatically downloads from APNIC if missing
- ✅ **Enhanced UI** - Clean hacker-style interface, Termux compatible
- ✅ **Summary Statistics** - Camera type breakdown and counts
- ✅ **Multiple Geolocation Services** - Fallback support for reliable location data

### 🔐 Login Validation Features

- ✅ **HIK Vision Camera Support** - ISAPI Digest Authentication
- ✅ **Dahua/Anjhua Camera Support** - HTTP API & RTSP validation
- ✅ **Multi-Threaded Brute Force** - Fast credential testing
- ✅ **Default Credentials Database** - Common admin passwords included

## Features

### 🌍 Country Support
- **44 Countries Supported** - Afghanistan, Australia, Bangladesh, Brunei, Bhutan, Cambodia, China, Fiji, Hong Kong, India, Indonesia, Japan, South Korea, Laos, Malaysia, Myanmar, Nepal, New Zealand, Pakistan, Philippines, Singapore, Sri Lanka, Taiwan, Thailand, Vietnam, and more!
- 🌐 **Auto-Fetch IP Ranges** - Automatically downloads from APNIC database if file missing

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

### 🌍 Supported Countries (44 Total)

Afghanistan, Australia, Bangladesh, Brunei, Bhutan, Cambodia, China, Cook Islands, Fiji, Micronesia, Guam, Hong Kong, India, Indonesia, Japan, Kiribati, South Korea, Sri Lanka, Laos, Myanmar, Mongolia, Macau, Maldives, Malaysia, New Caledonia, Nepal, Nauru, New Zealand, French Polynesia, Papua New Guinea, Philippines, Pakistan, North Korea, Palau, Solomon Islands, Singapore, Thailand, Timor-Leste, Tonga, Taiwan, Vanuatu, Vietnam, Samoa, and United States (APNIC region)

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




