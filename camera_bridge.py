"""
camera_bridge.py — Use your Android phone as a webcam for Windows.

No apps needed on the phone. Just open a browser and point it at this server.

============================================================================
SETUP
============================================================================

1. Install dependencies:
   pip install flask flask-socketio pyvirtualcam opencv-python numpy simple-websocket

   Optional (faster JPEG decoding — up to 4× speedup):
   pip install simplejpeg

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
CLI OPTIONS
============================================================================

  --width  W     Virtual camera width  (default: 1280)
  --height H     Virtual camera height (default: 720)
  --fps    N     Target frames per second (default: 30)
  --port   P     Server port (default: 5000)
  --no-ssl       Disable HTTPS (plain HTTP)

============================================================================
PERFORMANCE
============================================================================

This version uses a Producer-Consumer threading pattern:
- The SocketIO handler (producer) only enqueues raw binary data.
- A dedicated worker thread (consumer) decodes and sends to the virtual cam.
- Frames are dropped when the queue backs up, preventing lag buildup.

Binary JPEG blobs are sent over WebSockets (no Base64), reducing payload
size by ~33% and eliminating encode/decode overhead on both ends.

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

import argparse
import atexit
import os
import queue
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

import cv2
import numpy as np
import pyvirtualcam
from flask import Flask, render_template_string
from flask_socketio import SocketIO

# ---------------------------------------------------------------------------
# Try to import simplejpeg for faster JPEG decoding (up to 4× vs cv2)
# ---------------------------------------------------------------------------
try:
    import simplejpeg

    _USE_SIMPLEJPEG = True
    print("[✓] simplejpeg found — using fast JPEG decoder")
except ImportError:
    _USE_SIMPLEJPEG = False
    print("[i] simplejpeg not installed — using cv2 decoder (pip install simplejpeg for ~4× faster decode)")

# ---------------------------------------------------------------------------
# Default configuration (overridden by CLI arguments)
# ---------------------------------------------------------------------------
DEFAULT_WIDTH = 1280
DEFAULT_HEIGHT = 720
DEFAULT_FPS = 30
DEFAULT_PORT = 5000

# Maximum frames allowed in the queue before we start dropping
MAX_QUEUE_SIZE = 2

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
        let rafId         = null;
        let currentStream = null;
        let useFront      = false;   // start with rear camera
        let framesSent    = 0;
        let lastFpsTime   = performance.now();
        let sending       = false;   // back-pressure flag

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
                    width:  { ideal: {{ width }} },
                    height: { ideal: {{ height }} }
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
                    captureLoop();
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
            if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
            if (currentStream) {
                currentStream.getTracks().forEach(t => t.stop());
                currentStream = null;
            }
        }

        // ----- Frame capture & send (binary blob, with back-pressure) ---
        const TARGET_INTERVAL = 1000 / {{ fps }};
        let lastFrameTime = 0;

        function captureLoop(timestamp) {
            if (!streaming) return;
            rafId = requestAnimationFrame(captureLoop);

            // Throttle to target FPS
            if (timestamp - lastFrameTime < TARGET_INTERVAL) return;
            lastFrameTime = timestamp;

            // Back-pressure: skip if previous frame is still being encoded
            if (sending) return;
            sending = true;

            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

            // toBlob is async & faster than toDataURL; sends raw binary
            canvas.toBlob(blob => {
                if (!streaming) { sending = false; return; }
                blob.arrayBuffer().then(buf => {
                    socket.emit('video_frame', buf);
                    sending = false;

                    // FPS counter
                    framesSent++;
                    const now = performance.now();
                    if (now - lastFpsTime >= 1000) {
                        fpsEl.textContent = framesSent + ' FPS';
                        framesSent  = 0;
                        lastFpsTime = now;
                    }
                });
            }, 'image/jpeg', 0.7);
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


def _cert_matches_ip(local_ip: str) -> bool:
    """Check if the existing SSL certificate contains the current local IP in its SAN.
    
    Returns True if the cert is valid and contains the IP, False otherwise.
    """
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        return False

    # First try: use the cryptography library for accurate SAN inspection
    try:
        from cryptography import x509
        import ipaddress as _ipa

        with open(CERT_FILE, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        # Check expiry
        import datetime
        if cert.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc):
            print("[!] SSL certificate has expired")
            return False

        # Check SAN contains current IP
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            cert_ips = [str(ip) for ip in san.value.get_values_for_type(x509.IPAddress)]
            if local_ip in cert_ips:
                return True
            else:
                print(f"[!] SSL certificate SAN IPs {cert_ips} don't match current IP {local_ip}")
                return False
        except x509.ExtensionNotFound:
            print("[!] SSL certificate has no SAN extension")
            return False
    except ImportError:
        pass

    # Fallback: try loading the cert into an SSL context — if it fails, it's broken
    try:
        test_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        test_ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        # Can't check IP match without cryptography, but at least the cert loads
        print("[i] Cannot verify SAN (install 'cryptography' for IP validation)")
        return True
    except ssl.SSLError:
        print("[!] SSL certificate is corrupted or key mismatch")
        return False


def _delete_ssl_cert():
    """Remove existing SSL certificate and key files."""
    for path in (CERT_FILE, KEY_FILE):
        if os.path.exists(path):
            os.remove(path)
            print(f"[i] Deleted stale {os.path.basename(path)}")


def _generate_ssl_cert(local_ip: str) -> bool:
    """Generate a new self-signed certificate. Returns True on success."""
    print("[…] Generating self-signed SSL certificate …")

    # Try using openssl (often available on Windows via Git, Python, etc.)
    # A SAN (Subject Alternative Name) with the local IP is required so
    # that modern browsers (especially Android Chrome) accept the cert.
    try:
        # Write a minimal openssl config with SAN entries
        ext_cfg = (
            "[req]\n"
            "distinguished_name = req_dn\n"
            "x509_extensions = v3_ca\n"
            "prompt = no\n"
            "[req_dn]\n"
            "CN = CameraBridge\n"
            "O = Local\n"
            "C = US\n"
            "[v3_ca]\n"
            "subjectAltName = "
            f"IP:{local_ip},IP:127.0.0.1,DNS:localhost\n"
        )
        ext_path = os.path.join(tempfile.gettempdir(), "camera_bridge_ssl.cnf")
        with open(ext_path, "w") as f:
            f.write(ext_cfg)

        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", KEY_FILE,
                "-out", CERT_FILE,
                "-days", "365",
                "-nodes",
                "-config", ext_path,
            ],
            check=True,
            capture_output=True,
        )
        os.remove(ext_path)
        print(f"[✓] SSL certificate generated (openssl) — SAN: {local_ip}")
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
                    x509.IPAddress(ipaddress.IPv4Address(local_ip)),
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


def ensure_ssl_cert() -> bool:
    """Ensure a valid self-signed SSL certificate exists for the current local IP.
    
    Validates existing certs against the current IP and regenerates if stale,
    expired, or missing. Also verifies the SSL context can load the cert pair.
    Returns True if cert files are ready and loadable, False otherwise.
    """
    local_ip = get_local_ip()

    # Check if existing cert matches current IP
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        if _cert_matches_ip(local_ip):
            print(f"[✓] Reusing existing SSL certificate (SAN matches {local_ip})")
            return True
        else:
            print(f"[i] Regenerating SSL certificate for new IP: {local_ip}")
            _delete_ssl_cert()

    # Generate new cert
    if not _generate_ssl_cert(local_ip):
        return False

    # Final verification: make sure the SSL context can actually load it
    try:
        verify_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        verify_ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        print("[✓] SSL certificate verified — context loads OK")
        return True
    except ssl.SSLError as e:
        print(f"[✗] SSL certificate verification FAILED: {e}")
        _delete_ssl_cert()
        return False


def open_virtual_cam(width: int, height: int, fps: int) -> pyvirtualcam.Camera:
    """Try each preferred backend in order; fall back to the default."""
    for backend_name in PREFERRED_BACKENDS:
        try:
            cam = pyvirtualcam.Camera(
                width=width,
                height=height,
                fps=fps,
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
            width=width,
            height=height,
            fps=fps,
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


def decode_jpeg(jpg_bytes: bytes) -> np.ndarray | None:
    """Decode a JPEG buffer to a BGR numpy array.
    
    Uses simplejpeg when available (much faster), falls back to cv2.
    """
    if _USE_SIMPLEJPEG:
        try:
            # simplejpeg decodes directly to BGR (or any colorspace)
            return simplejpeg.decode_jpeg(jpg_bytes, colorspace="BGR")
        except Exception:
            return None
    else:
        np_arr = np.frombuffer(jpg_bytes, dtype=np.uint8)
        return cv2.imdecode(np_arr, cv2.IMREAD_COLOR)


# ---------------------------------------------------------------------------
# Flask + SocketIO App
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
virtual_cam: pyvirtualcam.Camera | None = None
frame_queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE + 2)
worker_running = threading.Event()

# Performance counters (printed every 5 seconds)
_perf_lock = threading.Lock()
_perf_frames_processed = 0
_perf_frames_dropped = 0
_perf_last_report = 0.0


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE, fps=cam_fps, width=cam_width, height=cam_height)


# ---------------------------------------------------------------------------
# Producer — SocketIO event handler (runs in the networking thread)
#
# This does zero image processing. It only enqueues raw bytes.
# ---------------------------------------------------------------------------
@socketio.on("video_frame")
def handle_frame(data):
    """Receive a JPEG frame (binary) and enqueue it for the worker thread."""
    global _perf_frames_dropped

    if virtual_cam is None:
        return

    # Accept raw binary data
    if isinstance(data, (bytes, bytearray)):
        jpg_bytes = bytes(data)
    else:
        # Legacy base64 fallback (shouldn't happen with the new frontend)
        import base64
        try:
            jpg_bytes = base64.b64decode(data)
        except Exception:
            return

    # If queue is backing up, drop oldest frames to stay real-time
    if frame_queue.qsize() > MAX_QUEUE_SIZE:
        try:
            while frame_queue.qsize() > 1:
                frame_queue.get_nowait()
                with _perf_lock:
                    _perf_frames_dropped += 1
        except queue.Empty:
            pass

    try:
        frame_queue.put_nowait(jpg_bytes)
    except queue.Full:
        # Queue is full — drop this frame (we're processing too slowly)
        with _perf_lock:
            _perf_frames_dropped += 1


# ---------------------------------------------------------------------------
# Consumer — Worker thread (decodes frames and sends to virtual cam)
#
# All heavy lifting (JPEG decode, resize, color conversion) happens here,
# completely decoupled from the network thread.
# ---------------------------------------------------------------------------
def process_frames():
    """Worker thread: pull frames from queue, decode, and send to virtual cam."""
    global _perf_frames_processed, _perf_frames_dropped, _perf_last_report

    _perf_last_report = time.monotonic()

    while worker_running.is_set():
        try:
            jpg_bytes = frame_queue.get(timeout=0.1)
        except queue.Empty:
            continue

        try:
            frame_bgr = decode_jpeg(jpg_bytes)
            if frame_bgr is None:
                continue

            # Resize only if dimensions don't match
            h, w = frame_bgr.shape[:2]
            if w != cam_width or h != cam_height:
                frame_bgr = cv2.resize(
                    frame_bgr, (cam_width, cam_height),
                    interpolation=cv2.INTER_LINEAR,
                )

            # BGR → RGB (pyvirtualcam expects RGB)
            frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)

            # Send to virtual camera
            virtual_cam.send(frame_rgb)

            with _perf_lock:
                _perf_frames_processed += 1

        except Exception as e:
            print(f"[!] Frame processing error: {e}")

        # Performance report every 5 seconds
        now = time.monotonic()
        with _perf_lock:
            if now - _perf_last_report >= 5.0:
                fps = _perf_frames_processed / (now - _perf_last_report)
                dropped = _perf_frames_dropped
                print(
                    f"[📊] {fps:.1f} FPS | "
                    f"processed: {_perf_frames_processed} | "
                    f"dropped: {dropped} | "
                    f"queue: {frame_queue.qsize()}"
                )
                _perf_frames_processed = 0
                _perf_frames_dropped = 0
                _perf_last_report = now

    print("[i] Worker thread stopped.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import ipaddress

    # ---- CLI argument parsing ------------------------------------------
    parser = argparse.ArgumentParser(
        description="Camera Bridge — use your Android phone as a Windows webcam.",
    )
    parser.add_argument(
        "--width", type=int, default=DEFAULT_WIDTH,
        help=f"Virtual camera output width in pixels (default: {DEFAULT_WIDTH})",
    )
    parser.add_argument(
        "--height", type=int, default=DEFAULT_HEIGHT,
        help=f"Virtual camera output height in pixels (default: {DEFAULT_HEIGHT})",
    )
    parser.add_argument(
        "--fps", type=int, default=DEFAULT_FPS,
        help=f"Target frames per second (default: {DEFAULT_FPS})",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"HTTP/HTTPS server port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--no-ssl", action="store_true",
        help="Disable HTTPS and run in plain HTTP mode",
    )
    args = parser.parse_args()

    # Expose parsed values to module-level scope so the Flask handlers
    # (which run outside __main__) can access them.
    cam_width = args.width
    cam_height = args.height
    cam_fps = args.fps
    server_port = args.port
    use_ssl = not args.no_ssl

    local_ip = get_local_ip()

    print("=" * 60)
    print("  📷  Camera Bridge  (High-Performance Mode)")
    print("=" * 60)
    print(f"  Resolution : {cam_width}×{cam_height} @ {cam_fps} FPS")
    print(f"  Port       : {server_port}")
    print(f"  Decoder    : {'simplejpeg (fast)' if _USE_SIMPLEJPEG else 'cv2 (standard)'}")
    print(f"  Queue      : max {MAX_QUEUE_SIZE} frames (drop oldest)")
    print()

    # Open virtual camera
    virtual_cam = open_virtual_cam(cam_width, cam_height, cam_fps)
    print()

    # Start the worker thread
    worker_running.set()
    worker_thread = threading.Thread(target=process_frames, daemon=True, name="FrameWorker")
    worker_thread.start()
    print("[✓] Worker thread started")

    # Ensure clean shutdown
    def _shutdown():
        worker_running.clear()
        worker_thread.join(timeout=2)
        if virtual_cam:
            virtual_cam.close()
        print("[✓] Clean shutdown complete")

    atexit.register(_shutdown)

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
    print(f"  → {protocol}://{local_ip}:{server_port}")
    print()
    if use_https:
        print("  Your phone will show a certificate warning.")
        print("  Tap 'Advanced' → 'Proceed' — this is safe (local cert).")
    else:
        print("  TIP: On Android Chrome, enable the flag")
        print("       'Insecure origins treated as secure'")
        print(f"       and add http://{local_ip}:{server_port}")
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
            port=server_port,
            ssl_context=ssl_ctx,
            allow_unsafe_werkzeug=True,
        )
    else:
        socketio.run(
            app,
            host="0.0.0.0",
            port=server_port,
            allow_unsafe_werkzeug=True,
        )
