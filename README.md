<h1 align="center">📷 Camera Bridge</h1>

<p align="center">
  <strong>Use your Android phone as a webcam for your Windows PC, over Wi-Fi.</strong><br>
  No app on the phone. No USB cable.
</p>

<p align="center">
  <img alt="Windows" src="https://img.shields.io/badge/Windows-10%20%2F%2011-0078D4?logo=windows&logoColor=white" />
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10–3.14-3776ab?logo=python&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green" />
</p>

---

## What you need

- A **Windows 10 or 11** PC
- An **Android phone** with **Chrome**, on the **same network** as the PC
- **[Python 3.14](https://www.python.org/downloads/)** (any version from 3.10 to 3.14 works)
- **[OBS Studio](https://obsproject.com)**. You don't need to open it; it just provides the "OBS Virtual Camera" that Zoom, Teams, Meet and Discord can use.

---

## Install (once)

1. Install **Python** and **OBS Studio** (links above). Default options are fine.
2. Download this project: click **Code → Download ZIP** on GitHub and unzip it, or run:
   ```bash
   git clone https://github.com/GuiGarciaDev/virtual-cam.git
   ```
3. Open the folder and **double-click `start.bat`**.

The first time takes about a minute while it installs what it needs. After that it starts right away.

If Windows asks whether to allow **Python** on the network, tick **Private networks** only and click **Allow**.

---

## Use it

Every time you want to use your phone as a webcam:

1. **Double-click `start.bat`.** A window opens with a **QR code**.
2. **Scan the QR code** with your phone's camera and open the link in Chrome.
3. **Allow camera access** on the phone. You'll see a preview and **Connected to PC**.
4. In **Zoom / Teams / Meet / Discord**, choose **OBS Virtual Camera** as your camera.
5. When you're done, **close the window** on the PC.

**Tips**
- Keep the Camera Bridge page **open and in front** on the phone during the call. The page keeps the screen on.
- Use **Flip camera** to switch between the back and front camera.
- **Bookmark the page** on your phone: the link stays the same every time, so next time you can skip the QR code.

### First time on a phone: the security warning

The first time, Chrome shows **"Your connection is not private"**. That's expected, because the page runs on your own PC.

- Tap **Advanced → Proceed** to continue.
- To make the warning go away for good, tap **Remove the certificate warning** at the bottom of the page and follow the steps there (download a small certificate and install it in your phone's settings).

---

## Settings (optional)

Add options after `start.bat`, for example in a Command Prompt opened in the project folder:

```bash
start.bat --fit crop
```

| Option          | What it does                                                                    |
| --------------- | ------------------------------------------------------------------------------- |
| `--fit crop`    | Fill the whole picture (cuts the edges) instead of showing black bars           |
| `--width 1920 --height 1080` | Full HD output (default is 1280 × 720)                             |
| `--fps 24`      | Fewer frames per second (default 30). Helps on slow Wi-Fi                        |
| `--quality 0.6` | Lower image quality (default 0.8). Helps on slow Wi-Fi                           |
| `--port 47800`  | Use another network port (default 5000)                                         |
| `--new-token`   | Make a new secret link. Old links and bookmarks stop working                    |

---

## Problems?

| Problem | What to do |
| ------- | ---------- |
| **"Python 3.10 - 3.14 was not found"** | Install [Python 3.14](https://www.python.org/downloads/), then run `start.bat` again. |
| **"Could not open a virtual camera"** | Install [OBS Studio](https://obsproject.com). If OBS is open with **Start Virtual Camera** on, stop it. |
| **The phone can't open the page** | 1. Phone and PC on the same network?<br>2. Your network must be **Private** on the PC: **Settings → Network & internet → Wi-Fi or Ethernet → your network → Network profile type → Private**. Do this only for your home network.<br>3. Allow Python in **Windows Security → Firewall & network protection → Allow an app through firewall** (tick **Private**). |
| **"Access denied" on the phone** | The link changed. Scan the new QR code. |
| **The meeting shows "Waiting for phone..."** | The page on the phone is closed, in the background, or the screen is off. |
| **The picture lags** | Try `start.bat --quality 0.6 --fps 24`, or move closer to the router. |
| **Something else broke** | Delete the `.venv` folder and run `start.bat` again. It reinstalls everything. |

---

## Is it safe?

- **Encrypted:** the video travels over HTTPS, like a banking website.
- **Secret link:** the QR code contains a secret code. Without it, other devices on your network can't open the page or send video. Keep the link to yourself.
- **One phone at a time:** if another phone connects with the link, the first one is disconnected.
- **Not on the internet:** only devices on your own network can reach it, and only while `start.bat` is running.
- **The certificate** you can install on the phone only works for home-network addresses (like 192.168.x.x), so it can't be used to fake real websites. You can remove it any time in the phone's settings under **Encryption & credentials → User credentials**.

Your secret link and certificate are stored in the `camera_bridge_data` folder on your PC. They're never uploaded to GitHub.

---

## How it works

```
📱 Chrome on the phone ──(encrypted Wi-Fi)──▶ 🖥️ camera_bridge.py ──▶ 🎥 OBS Virtual Camera ──▶ Zoom, Teams, Meet...
```

The phone page captures the camera and sends JPEG images to the PC. The script fits each image to the webcam size
without stretching it and passes it to the virtual camera. If the Wi-Fi gets slow, frames are skipped so the
video never falls behind.

| File               | Purpose                                         |
| ------------------ | ----------------------------------------------- |
| `start.bat`        | Double-click to set up and start everything     |
| `camera_bridge.py` | The app (PC server and the phone page)          |
| `requirements.txt` | Python packages it needs                        |

---

## License

MIT. See [LICENSE](LICENSE).
