# 🌐 Modern Proxy Checker

A powerful and modern GUI application for checking and validating proxy servers with multi-protocol support.

## ✨ Features

- 🎨 **Modern & user-friendly GUI**
- 🔄 **Multi-protocol support** (HTTP, HTTPS, SOCKS4, SOCKS5)
- ⚡ **Multi-threaded proxy checking**
- 📊 **Real-time progress tracking**
- 📈 **Visual statistics with charts**
- 🕵️ **Proxy anonymity level detection**
- 📂 **Export results in TXT & JSON formats**
- 🔗 **Customizable test URLs**
- ✍️ **Manual proxy input support**

## 📥 Installation

1️⃣ Install the required packages:
```bash
pip install -r requirements.txt
```

2️⃣ Run the application:
```bash
python modern_proxy_checker.py
```

## 🛠 Usage

### 📁 File Settings
- 📌 Load proxy list from a text file
- 💾 Set output file for saving results

### ⚙️ Checker Settings
- 🔢 Adjust **number of threads** (1-100)
- ⏳ Set **timeout duration** (1-30 seconds)
- 🔗 Add/modify **test URLs**

### ✍️ Manual Input
- ➕ Enter proxies manually (one per line)
- 🔹 Format: `ip:port` or `hostname:port`
- 📌 Example:
  ```
  192.168.1.1:8080
  proxy.example.com:3128
  ```

### 🎮 Controls
- ▶️ **Start** - Begin proxy checking
- ⏹ **Stop** - Stop the current check
- 🔄 **Reset** - Clear all settings and results
- ℹ️ **Info** - Show application information

## 📊 Results

The application provides:
- 🚀 **Real-time progress tracking**
- 📊 **Working proxy statistics**
- 🗂 **Proxy type distribution chart**
- ✅ **List of working proxies**
- 📤 **Export options** (TXT & detailed JSON)

## 📋 Requirements

- 🐍 **Python 3.7+**
- 🖥 **PyQt5**
- 🌐 **Requests**
- 🔗 **urllib3**
- 📉 **matplotlib**

## 👨‍💻 Developer

Created by **[Captain MGC](https://github.com/captainmgc)** 🚀

## 📜 License

This project is licensed under the **MIT License** 📄

