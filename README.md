<h1 align="center">📷 Camera Bridge</h1>

<p align="center">
  <strong>Turn your Android phone into a Windows webcam — no app install required.</strong>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776ab?logo=python&logoColor=white" />
  <img alt="Flask" src="https://img.shields.io/badge/Flask-SocketIO-000?logo=flask&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green" />
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Windows-0078D4?logo=windows&logoColor=white" />
</p>

---

## ✨ What Is This?

**Camera Bridge** is a lightweight Python script that streams your Android phone's camera directly to a Windows virtual webcam — all through the browser. No companion app needed on the phone.

Just run the script on your PC, open a URL on your phone, and your phone camera instantly becomes available as a webcam in **Zoom, Discord, Google Meet, OBS**, or any other application that accepts a camera input.

### How It Works

```
📱 Phone Browser ─── WebSocket (JPEG frames) ───▶ 🖥️ Python Server ───▶ 🎥 Virtual Webcam
        ↑                                                ↑
   getUserMedia API                              OpenCV + pyvirtualcam
   (HTTPS required)                              (decodes & forwards)
```

1. The phone opens an HTTPS page served by the Python script
2. The browser captures camera frames using the `getUserMedia` API
3. Frames are sent as Base64-encoded JPEG via **Socket.IO** (WebSocket)
4. The server decodes each frame with **OpenCV**, resizes it, and pushes it to a **virtual camera** device on Windows

---

## 🚀 Quick Start

### Prerequisites

| Requirement               | Purpose                                                                                                                                 |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Python 3.10+**          | Runtime                                                                                                                                 |
| **Virtual camera driver** | [Unity Capture](https://github.com/schellingb/UnityCapture) **or** [OBS Studio](https://obsproject.com) (ships with OBS Virtual Camera) |
| **Android phone**         | On the same Wi-Fi / LAN as your PC                                                                                                      |

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/camera-bridge.git
cd camera-bridge
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS (if ever ported)
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the server

```bash
python camera_bridge.py                # defaults: 1280×720 @ 30 FPS, port 5000
python camera_bridge.py --help         # see all options
```

The script will:

- Open the virtual camera device
- Auto-generate a self-signed SSL certificate (first run only)
- Start an HTTPS server and print the URL to open on your phone

### 5. Open on your phone

Navigate to the URL shown in the terminal (e.g. `https://192.168.1.42:5000`).

> [!NOTE]
> Your phone's browser will warn you about the self-signed certificate.
> Tap **Advanced → Proceed** — this is safe since the certificate is local and only used on your LAN.

Once the page loads, your phone camera feed will appear as a regular webcam on Windows! 🎉

---

## ⚙️ Configuration

All settings can be customised via **command-line arguments**:

| Flag         | Default | Description                       |
| ------------ | ------- | --------------------------------- |
| `--width W`  | `1280`  | Virtual camera output width (px)  |
| `--height H` | `720`   | Virtual camera output height (px) |
| `--fps N`    | `30`    | Target frames per second          |
| `--port P`   | `5000`  | HTTP/HTTPS server port            |
| `--no-ssl`   | off     | Disable HTTPS (plain HTTP mode)   |

### Examples

```bash
# 1080p at 60 FPS on port 8080
python camera_bridge.py --width 1920 --height 1080 --fps 60 --port 8080

# 480p, default FPS, no SSL
python camera_bridge.py --width 854 --height 480 --no-ssl
```

---

## 🔒 SSL & HTTPS

Modern mobile browsers require a **secure context** (HTTPS) to access the camera via `getUserMedia`. Camera Bridge handles this automatically:

- On first run, a **self-signed SSL certificate** is generated and saved next to the script
- The certificate is reused on subsequent runs
- Certificate generation uses either `openssl` (if available) or the Python `cryptography` library

### Prefer plain HTTP?

Pass `--no-ssl` and configure Chrome on Android:

1. Go to `chrome://flags`
2. Search for **"Insecure origins treated as secure"**
3. Add `http://<YOUR_PC_IP>:5000` and enable the flag
4. Relaunch Chrome

---

## 📁 Project Structure

```
camera-bridge/
├── camera_bridge.py      # Main application (server + embedded frontend)
├── requirements.txt      # Python dependencies
├── .gitignore            # Git ignore rules
├── LICENSE               # MIT License
└── README.md             # This file
```

> [!TIP]
> The HTML/CSS/JS frontend is embedded directly inside `camera_bridge.py` — it's a single-file application with zero external build steps.

---

## 🛠️ Supported Virtual Camera Backends

The script tries the following backends in order:

1. **Unity Capture** — lightweight, standalone virtual camera driver
2. **OBS Virtual Camera** — included with OBS Studio
3. **Default** — falls back to whatever `pyvirtualcam` auto-detects

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with ❤️ for everyone tired of buying overpriced webcams.
</p>
