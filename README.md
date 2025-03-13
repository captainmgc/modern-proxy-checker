![Logo MPC](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiha1cysGLbQZra_rCUsLbEa2Ix0NVk1wBPPvQMXNalJQypJO7awcQOagV4tPgtlFtJrnZAFjUO2nXfCnw4U6G_Y1ZM0jtiIZwdrZqbUBAuRX7tuHTTO4G3ll1_AkoU1SilbWmlY6oM1XWvmzIqeTseXtOBusfs2mH0LfM6RN-xVIagUv6Nle1fr_3OMFU/s16000/logo-mpc.png)


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
  ![app](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiyO7bOQc7VcrbDMzTj5n4lyAsCDIGLlCGUi_lQGGCs_PzsSRsuIl6z_L0bbMKBHvkqcNki-7vNRwtQldnXioC0vEYAOI35SBlwEmn5Vhi53cqy1Ck5-eUDkBLzGlPaD3eC4zjwTQcJzgXCswqMrxH8tPdxY6IhSyPNGt_b_gNImb1GZsfoET8wfjqKj2k/s16000/screenview2.png)

  ![app2](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgh5KMa_kx6g49rsSUV4xvKOYdAQyBbItFM-DJIYeIS46APS_SJPHKHuIKt0S5Vm6BzPOv45FKv1IkEGkmppz3LYP6Zmf9QKkRm_B4xQy0pHsqcBZH-Uh9sNu_RbEW6R6_GWtDsR198qt3d167OV0pm27l7EgvnDm-2aUURmENb0CQLsvckVTB8KZtueKM/s16000/Ekran%20g%C3%B6r%C3%BCnt%C3%BCs%C3%BC%202025-03-13%20153839.png)

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

