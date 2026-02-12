"""
camera_bridge.py — Use your Android phone as a webcam for Windows.

No apps needed on the phone. Just open a browser and point it at this server.

============================================================================
SETUP
============================================================================

1. Install dependencies:
   pip install flask flask-socketio pyvirtualcam opencv-python numpy simple-websocket

2. Install a Virtual Camera driver on Windows:
   - Unity Capture:  https://github.com/schellingb/UnityCapture
   - OBS Virtual Cam: Install OBS Studio — it includes OBS Virtual Camera.

3. Run this script:
   python camera_bridge.py

4. On your Android phone, open Chrome and navigate to:
   https://<YOUR_PC_LOCAL_IP>:5000

   Your browser will warn about the self-signed certificate.
   Tap "Advanced" → "Proceed to <IP> (unsafe)" to continue.
   This is safe — the cert is local and only used on your LAN.

============================================================================
NOTE — SELF-SIGNED HTTPS
============================================================================

This script automatically generates a temporary self-signed SSL certificate
so that the browser treats the page as a secure context (required for camera
access). The cert files are written to the script's directory and reused on
subsequent runs.

If you prefer plain HTTP, pass --no-ssl and configure Chrome on Android:
  1. Open chrome://flags
  2. Search for "Insecure origins treated as secure"
  3. Add http://<YOUR_PC_LOCAL_IP>:5000 and enable the flag
  4. Relaunch Chrome
============================================================================
"""

import base64
import os
import socket
import ssl
import subprocess
import sys
import tempfile

import cv2
import numpy as np
import pyvirtualcam
from flask import Flask, render_template_string
from flask_socketio import SocketIO

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
VIRTUAL_CAM_WIDTH = 1280
VIRTUAL_CAM_HEIGHT = 720
VIRTUAL_CAM_FPS = 30
SERVER_PORT = 5000

# Preferred virtual-camera backends (tried in order)
PREFERRED_BACKENDS = [
    "Unity Video Capture",
    "OBS Virtual Camera",
]

# SSL cert paths (next to this script)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(SCRIPT_DIR, "camera_bridge_cert.pem")
KEY_FILE = os.path.join(SCRIPT_DIR, "camera_bridge_key.pem")

# ---------------------------------------------------------------------------
# HTML / JS Frontend (embedded)
# ---------------------------------------------------------------------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Camera Bridge</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0f0f0f;
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }

        h1 {
            font-size: 1.4rem;
            margin-bottom: 0.5rem;
            color: #7ec8e3;
        }

        #status {
            font-size: 0.9rem;
            padding: 4px 12px;
            border-radius: 12px;
            margin-bottom: 1rem;
            transition: background 0.3s;
        }
        #status.connected    { background: #1b5e20; color: #a5d6a7; }
        #status.disconnected { background: #b71c1c; color: #ef9a9a; }
        #status.waiting      { background: #e65100; color: #ffcc80; }

        #error-banner {
            display: none;
            background: #b71c1c;
            color: #fff;
            padding: 16px 20px;
            border-radius: 12px;
            margin-bottom: 1rem;
            max-width: 90vw;
            font-size: 0.85rem;
            line-height: 1.5;
            text-align: left;
        }
        #error-banner strong { color: #ffcdd2; }
        #error-banner code {
            background: rgba(255,255,255,.15);
            padding: 1px 5px;
            border-radius: 4px;
            font-size: 0.8rem;
        }

        #preview-container {
            position: relative;
            width: 90vw;
            max-width: 640px;
            aspect-ratio: 16 / 9;
            background: #1a1a1a;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 24px rgba(0,0,0,.6);
        }

        video, canvas {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        /* The canvas is used only for capture — keep it invisible */
        canvas { display: none; }

        #fps-counter {
            position: absolute;
            top: 8px;
            right: 10px;
            font-size: 0.75rem;
            background: rgba(0,0,0,.55);
            padding: 2px 8px;
            border-radius: 6px;
            color: #7ec8e3;
        }

        .controls {
            margin-top: 1rem;
            display: flex;
            gap: 0.5rem;
        }

        button {
            padding: 8px 20px;
            border: none;
            border-radius: 8px;
            font-size: 0.9rem;
            cursor: pointer;
            transition: background 0.2s;
        }

        #btn-start {
            background: #2196f3;
            color: #fff;
        }
        #btn-start:hover { background: #1976d2; }

        #btn-stop {
            background: #616161;
            color: #fff;
        }
        #btn-stop:hover { background: #424242; }

        #btn-flip {
            background: #00897b;
            color: #fff;
        }
        #btn-flip:hover { background: #00695c; }
    </style>
</head>
<body>
    <h1>📷 Camera Bridge</h1>
    <div id="status" class="waiting">Connecting…</div>

    <div id="error-banner"></div>

    <div id="preview-container">
        <video id="video" autoplay playsinline muted></video>
        <canvas id="canvas"></canvas>
        <div id="fps-counter">0 FPS</div>
    </div>

    <div class="controls">
        <button id="btn-start">Start</button>
        <button id="btn-stop">Stop</button>
        <button id="btn-flip">Flip Camera</button>
    </div>

    <script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
    <script>
        // ----- Elements -------------------------------------------------
        const video       = document.getElementById('video');
        const canvas      = document.getElementById('canvas');
        const ctx         = canvas.getContext('2d');
        const statusEl    = document.getElementById('status');
        const fpsEl       = document.getElementById('fps-counter');
        const errorBanner = document.getElementById('error-banner');
        const btnStart    = document.getElementById('btn-start');
        const btnStop     = document.getElementById('btn-stop');
        const btnFlip     = document.getElementById('btn-flip');

        // ----- State ----------------------------------------------------
        let streaming     = false;
        let sendTimer     = null;
        let currentStream = null;
        let useFront      = false;   // start with rear camera
        let framesSent    = 0;
        let lastFpsTime   = performance.now();

        // ----- Socket.IO ------------------------------------------------
        const socket = io();

        socket.on('connect', () => {
            statusEl.textContent = 'Connected';
            statusEl.className  = 'connected';
        });

        socket.on('disconnect', () => {
            statusEl.textContent = 'Disconnected';
            statusEl.className  = 'disconnected';
        });

        // ----- Error display --------------------------------------------
        function showError(title, detail) {
            errorBanner.innerHTML = '<strong>' + title + '</strong><br>' + detail;
            errorBanner.style.display = 'block';
        }

        // ----- Camera ---------------------------------------------------
        async function startCamera() {
            // Stop existing stream first
            stopCamera();
            errorBanner.style.display = 'none';

            // Check if mediaDevices API is available (requires secure context)
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                const proto = location.protocol;
                if (proto === 'http:') {
                    showError(
                        '🔒 Camera blocked — insecure context (HTTP)',
                        'Your browser requires <strong>HTTPS</strong> to access the camera.<br><br>' +
                        '<strong>Option 1:</strong> Access this page via <code>https://</code> instead of <code>http://</code>. ' +
                        'Accept the self-signed certificate warning.<br><br>' +
                        '<strong>Option 2 (Chrome):</strong> Go to <code>chrome://flags</code>, search for ' +
                        '"<em>Insecure origins treated as secure</em>", add <code>' + location.origin + '</code>, ' +
                        'enable the flag, and relaunch.'
                    );
                } else {
                    showError(
                        '🔒 Camera API not available',
                        'Your browser does not support <code>navigator.mediaDevices</code>. ' +
                        'Try using Chrome or Edge.'
                    );
                }
                return;
            }

            const constraints = {
                video: {
                    facingMode: useFront ? 'user' : { ideal: 'environment' },
                    width:  { ideal: 1280 },
                    height: { ideal: 720 }
                },
                audio: false
            };

            try {
                currentStream = await navigator.mediaDevices.getUserMedia(constraints);
                video.srcObject = currentStream;

                // Wait until the video has actual dimensions
                video.onloadedmetadata = () => {
                    canvas.width  = video.videoWidth;
                    canvas.height = video.videoHeight;
                    streaming = true;
                    scheduleSend();
                };
            } catch (err) {
                showError(
                    '📷 Camera error',
                    err.message + '<br><br>Make sure you have granted camera permission.'
                );
            }
        }

        function stopCamera() {
            streaming = false;
            if (sendTimer) { clearTimeout(sendTimer); sendTimer = null; }
            if (currentStream) {
                currentStream.getTracks().forEach(t => t.stop());
                currentStream = null;
            }
        }

        // ----- Frame sending loop (~30 FPS) -----------------------------
        const FRAME_INTERVAL = 1000 / 30;   // ~33 ms

        function scheduleSend() {
            if (!streaming) return;
            sendTimer = setTimeout(() => {
                sendFrame();
                scheduleSend();
            }, FRAME_INTERVAL);
        }

        function sendFrame() {
            if (!streaming) return;
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            const dataUrl = canvas.toDataURL('image/jpeg', 0.7);
            // Strip the "data:image/jpeg;base64," prefix
            const b64 = dataUrl.split(',')[1];
            socket.emit('video_frame', b64);

            // FPS counter
            framesSent++;
            const now = performance.now();
            if (now - lastFpsTime >= 1000) {
                fpsEl.textContent = framesSent + ' FPS';
                framesSent  = 0;
                lastFpsTime = now;
            }
        }

        // ----- Button handlers ------------------------------------------
        btnStart.addEventListener('click', startCamera);
        btnStop.addEventListener('click', stopCamera);
        btnFlip.addEventListener('click', () => {
            useFront = !useFront;
            if (currentStream) startCamera();   // restart with new facing
        });

        // Auto-start on page load
        startCamera();
    </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_local_ip() -> str:
    """Return the LAN IP address of this machine (best guess)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ensure_ssl_cert() -> bool:
    """Generate a self-signed certificate if one doesn't exist yet.
    
    Uses Python's ssl module to create the cert via openssl command.
    Returns True if cert files are ready, False otherwise.
    """
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        print("[✓] Reusing existing SSL certificate")
        return True

    print("[…] Generating self-signed SSL certificate …")

    # Try using openssl (often available on Windows via Git, Python, etc.)
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", KEY_FILE,
                "-out", CERT_FILE,
                "-days", "365",
                "-nodes",
                "-subj", "/CN=CameraBridge/O=Local/C=US",
            ],
            check=True,
            capture_output=True,
        )
        print("[✓] SSL certificate generated (openssl)")
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    # Try using Python's cryptography library if installed
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "CameraBridge"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.IPAddress(ipaddress.IPv4Address(get_local_ip())),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    x509.DNSName("localhost"),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("[✓] SSL certificate generated (cryptography)")
        return True
    except ImportError:
        pass

    print("[!] Could not generate SSL certificate.")
    print("    Install 'cryptography' for auto-generated certs:")
    print("      pip install cryptography")
    return False


def open_virtual_cam() -> pyvirtualcam.Camera:
    """Try each preferred backend in order; fall back to the default."""
    for backend_name in PREFERRED_BACKENDS:
        try:
            cam = pyvirtualcam.Camera(
                width=VIRTUAL_CAM_WIDTH,
                height=VIRTUAL_CAM_HEIGHT,
                fps=VIRTUAL_CAM_FPS,
                device=backend_name,
                print_fps=False,
            )
            print(f"[✓] Virtual camera opened: {backend_name}")
            return cam
        except Exception as e:
            print(f"[!] Could not open '{backend_name}': {e}")

    # Last resort — let pyvirtualcam pick whichever backend it finds
    try:
        cam = pyvirtualcam.Camera(
            width=VIRTUAL_CAM_WIDTH,
            height=VIRTUAL_CAM_HEIGHT,
            fps=VIRTUAL_CAM_FPS,
            print_fps=False,
        )
        print(f"[✓] Virtual camera opened (default backend): {cam.device}")
        return cam
    except Exception as e:
        print(f"\n[✗] Failed to open ANY virtual camera: {e}")
        print("    Make sure one of the following is installed:")
        print("      • Unity Capture  — https://github.com/schellingb/UnityCapture")
        print("      • OBS Studio     — https://obsproject.com  (includes OBS Virtual Camera)")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Flask + SocketIO App
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

virtual_cam: pyvirtualcam.Camera | None = None


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@socketio.on("video_frame")
def handle_frame(data: str):
    """Receive a Base64-encoded JPEG frame and push it to the virtual cam."""
    global virtual_cam
    if virtual_cam is None:
        return

    try:
        # Decode Base64 → raw bytes → NumPy array → OpenCV image (BGR)
        jpg_bytes = base64.b64decode(data)
        np_arr = np.frombuffer(jpg_bytes, dtype=np.uint8)
        frame_bgr = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

        if frame_bgr is None:
            return

        # Resize to match the virtual camera resolution
        frame_bgr = cv2.resize(frame_bgr, (VIRTUAL_CAM_WIDTH, VIRTUAL_CAM_HEIGHT))

        # Convert BGR → RGB (pyvirtualcam expects RGB)
        frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)

        # Send to virtual camera
        virtual_cam.send(frame_rgb)

    except Exception as e:
        print(f"[!] Frame error: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import ipaddress

    use_ssl = "--no-ssl" not in sys.argv
    local_ip = get_local_ip()

    print("=" * 60)
    print("  📷  Camera Bridge")
    print("=" * 60)
    print()

    # Open virtual camera
    virtual_cam = open_virtual_cam()
    print()

    # SSL setup
    use_https = False
    protocol = "http"
    if use_ssl:
        if ensure_ssl_cert():
            use_https = True
            protocol = "https"
            print()
        else:
            print("[!] Falling back to HTTP (no SSL).")
            print("    Camera access may be blocked on mobile browsers.")
            print()

    print(f"  Open this URL on your Android phone's browser:")
    print(f"  → {protocol}://{local_ip}:{SERVER_PORT}")
    print()
    if use_https:
        print("  Your phone will show a certificate warning.")
        print("  Tap 'Advanced' → 'Proceed' — this is safe (local cert).")
    else:
        print("  TIP: On Android Chrome, enable the flag")
        print("       'Insecure origins treated as secure'")
        print(f"       and add http://{local_ip}:{SERVER_PORT}")
    print()
    print("  To disable SSL: python camera_bridge.py --no-ssl")
    print()
    print("=" * 60)

    if use_https:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        socketio.run(
            app,
            host="0.0.0.0",
            port=SERVER_PORT,
            ssl_context=ssl_ctx,
            allow_unsafe_werkzeug=True,
        )
    else:
        socketio.run(
            app,
            host="0.0.0.0",
            port=SERVER_PORT,
            allow_unsafe_werkzeug=True,
        )
