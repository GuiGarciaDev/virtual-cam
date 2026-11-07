"""
camera_bridge.py: use your Android phone as a Windows webcam over Wi-Fi.

No app on the phone: it opens a page in Chrome, and the frames end up in a
virtual camera (OBS Virtual Camera or Unity Capture) that Zoom, Teams, Meet,
Discord, etc. can pick.

Security model (see README.md, "Security"):
  * HTTPS with a certificate signed by a small personal certificate
    authority (CA) that is created once on this PC. Install that CA on the
    phone once and the browser warning is gone for good, even when the PC's
    IP changes. The CA is name-constrained to private network addresses.
  * A secret access token in the URL (shown as a QR code). Pages and video
    connections without it are rejected.
  * Only one phone streams at a time: a new authorised connection replaces
    the previous one.

Run:  python camera_bridge.py            (python camera_bridge.py --help)
"""

from __future__ import annotations

import argparse
import datetime as dt
import hmac
import ipaddress
import json
import logging
import os
import secrets
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# Windows consoles that are not UTF-8 (or redirected output) would crash on
# the symbols printed below; make printing never fail.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except (AttributeError, ValueError):
        pass

import cv2
import numpy as np
from flask import Flask, Response, abort, render_template_string, request
from flask_sock import Sock

try:
    import simplejpeg  # optional, faster JPEG decoding
except ImportError:
    simplejpeg = None

try:
    import segno  # optional, QR code in the terminal
except ImportError:
    segno = None

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "camera_bridge_data"
CA_CERT_FILE = DATA_DIR / "ca_cert.pem"
CA_KEY_FILE = DATA_DIR / "ca_key.pem"
SERVER_CERT_FILE = DATA_DIR / "server_cert.pem"
SERVER_KEY_FILE = DATA_DIR / "server_key.pem"
TOKEN_FILE = DATA_DIR / "token.txt"
QR_FILE = DATA_DIR / "connect_qr.png"

CA_VALID_DAYS = 3650
SERVER_CERT_VALID_DAYS = 397          # browsers dislike leaf certs > 398 days
RENEW_BEFORE_DAYS = 30

# The CA may only vouch for these addresses, so even if its key leaked it
# could not be used to impersonate a real website on the phone.
PERMITTED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",   # carrier-grade NAT / Tailscale
    )
]

BACKENDS = ["obs", "unitycapture"]
IDLE_SECONDS = 2.0                    # show "waiting" image after this long
WS_MAX_MESSAGE = 8 * 1024 * 1024
HEARTBEAT_TIMEOUT = 15                # seconds without frames or heartbeat

log = logging.getLogger("camera_bridge")


@dataclass
class Config:
    width: int
    height: int
    fps: int
    quality: float
    fit: str            # "pad" or "crop"
    port: int
    host: str
    use_ssl: bool
    backend: str
    dry_run: bool
    new_token: bool


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def is_permitted_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in PERMITTED_NETWORKS)


def get_local_ips() -> list[str]:
    """Private IPv4 addresses of this PC, most likely LAN address first."""
    ips: list[str] = []

    # The address used for the default route is usually the Wi-Fi/Ethernet one.
    # (UDP connect sends no packets.)
    for probe in ("10.255.255.255", "8.8.8.8"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((probe, 1))
                ip = s.getsockname()[0]
            if ip not in ips:
                ips.append(ip)
        except OSError:
            pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except OSError:
        pass

    ips = [ip for ip in ips if is_permitted_ip(ip) and not ip.startswith("127.")]
    return ips or ["127.0.0.1"]


# ---------------------------------------------------------------------------
# Certificates (personal CA + server certificate)
# ---------------------------------------------------------------------------
def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_or_create_ca():
    """Return (ca_cert, ca_key), creating the CA on first run."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    if CA_CERT_FILE.exists() and CA_KEY_FILE.exists():
        try:
            cert = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())
            key = serialization.load_pem_private_key(CA_KEY_FILE.read_bytes(), None)
            if cert.not_valid_after_utc - _now() > dt.timedelta(days=RENEW_BEFORE_DAYS):
                return cert, key
            print("[!] The personal CA is about to expire; creating a new one.")
            print("    You will need to install the new CA on your phone again.")
        except Exception as e:  # corrupted files
            print(f"[!] Could not load the personal CA ({e}); creating a new one.")

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"Camera Bridge Local CA ({socket.gethostname()})"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Camera Bridge"),
    ])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=5))
        .not_valid_after(_now() + dt.timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("localhost")]
                + [x509.IPAddress(net) for net in PERMITTED_NETWORKS],
                excluded_subtrees=None,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )

    DATA_DIR.mkdir(exist_ok=True)
    _write_private(CA_KEY_FILE, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    CA_CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    # Force a new server certificate signed by this CA.
    SERVER_CERT_FILE.unlink(missing_ok=True)
    print("[✓] Created your personal certificate authority (one-time setup)")
    return cert, key


def _server_cert_ok(ca_cert, ips: list[str]) -> bool:
    from cryptography import x509

    if not (SERVER_CERT_FILE.exists() and SERVER_KEY_FILE.exists()):
        return False
    try:
        cert = x509.load_pem_x509_certificate(SERVER_CERT_FILE.read_bytes())
        if cert.issuer != ca_cert.subject:
            return False
        ca_cert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            *_sig_args(ca_cert, cert),
        )
        if cert.not_valid_after_utc - _now() < dt.timedelta(days=RENEW_BEFORE_DAYS):
            return False
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        cert_ips = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
        return set(ips) <= cert_ips
    except Exception:
        return False


def _sig_args(ca_cert, cert):
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    pub = ca_cert.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return (ec.ECDSA(cert.signature_hash_algorithm),)
    if isinstance(pub, rsa.RSAPublicKey):
        return (padding.PKCS1v15(), cert.signature_hash_algorithm)
    raise ValueError("unsupported CA key type")


def ensure_certificates(ips: list[str]) -> None:
    """Make sure a server certificate for all `ips`, signed by the CA, exists."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    ca_cert, ca_key = load_or_create_ca()
    if _server_cert_ok(ca_cert, ips):
        return

    san_ips = sorted({*ips, "127.0.0.1"}, key=ipaddress.ip_address)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Camera Bridge")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=5))
        .not_valid_after(_now() + dt.timedelta(days=SERVER_CERT_VALID_DAYS))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost")]
                + [x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_private(SERVER_KEY_FILE, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    SERVER_CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[✓] Server certificate issued for {', '.join(san_ips)}")


def make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(SERVER_CERT_FILE, SERVER_KEY_FILE)
    return ctx


# ---------------------------------------------------------------------------
# Access token
# ---------------------------------------------------------------------------
def load_or_create_token(rotate: bool) -> str:
    DATA_DIR.mkdir(exist_ok=True)
    if not rotate and TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text(encoding="ascii").strip()
        if len(token) >= 16:
            return token
    token = secrets.token_urlsafe(18)
    _write_private(TOKEN_FILE, token.encode("ascii"))
    print("[✓] New access token created" + (" (old links no longer work)" if rotate else ""))
    return token


def token_ok(candidate: str | None, token: str) -> bool:
    return bool(candidate) and hmac.compare_digest(candidate.encode(), token.encode())


# ---------------------------------------------------------------------------
# Frame handling
# ---------------------------------------------------------------------------
class FrameSlot:
    """Holds only the newest frame. Older, unprocessed frames are dropped,
    so the webcam never lags behind the phone."""

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._data: bytes | None = None
        self.dropped = 0

    def put(self, data: bytes) -> None:
        with self._cond:
            if self._data is not None:
                self.dropped += 1
            self._data = data
            self._cond.notify()

    def take(self, timeout: float) -> bytes | None:
        with self._cond:
            if self._data is None:
                self._cond.wait(timeout)
            data, self._data = self._data, None
            return data


def decode_jpeg(data: bytes) -> np.ndarray | None:
    if simplejpeg is not None:
        try:
            return simplejpeg.decode_jpeg(data, colorspace="BGR")
        except Exception:
            return None
    return cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)


def fit_frame(frame: np.ndarray, width: int, height: int, mode: str) -> np.ndarray:
    """Fit `frame` into width×height without distorting it.

    pad:  whole picture visible, black bars where the shape differs.
    crop: picture fills the output, edges are cut off.
    """
    h, w = frame.shape[:2]
    if (w, h) == (width, height):
        return frame
    scale = min(width / w, height / h) if mode == "pad" else max(width / w, height / h)
    nw, nh = max(1, round(w * scale)), max(1, round(h * scale))
    interp = cv2.INTER_AREA if scale < 1 else cv2.INTER_LINEAR
    resized = cv2.resize(frame, (nw, nh), interpolation=interp)

    if mode == "pad":
        if (nw, nh) == (width, height):
            return resized
        out = np.zeros((height, width, 3), dtype=np.uint8)
        x, y = (width - nw) // 2, (height - nh) // 2
        out[y:y + nh, x:x + nw] = resized
        return out

    x, y = (nw - width) // 2, (nh - height) // 2
    return np.ascontiguousarray(resized[y:y + height, x:x + width])


def make_placeholder(width: int, height: int, text: str) -> np.ndarray:
    img = np.full((height, width, 3), 24, dtype=np.uint8)
    font = cv2.FONT_HERSHEY_SIMPLEX
    scale = max(0.6, width / 1280)
    thickness = max(1, round(2 * scale))
    (tw, th), _ = cv2.getTextSize(text, font, scale, thickness)
    cv2.putText(img, text, ((width - tw) // 2, (height + th) // 2), font, scale,
                (200, 200, 200), thickness, cv2.LINE_AA)
    return img


class DryRunCamera:
    """Stands in for the virtual camera with --dry-run."""

    device = "dry run (no virtual camera)"

    def __init__(self) -> None:
        self.last_frame: np.ndarray | None = None

    def send(self, frame: np.ndarray) -> None:
        self.last_frame = frame

    def close(self) -> None:
        pass


def open_virtual_cam(cfg: Config):
    if cfg.dry_run:
        return DryRunCamera()

    try:
        import pyvirtualcam
    except ImportError:
        print("[✗] pyvirtualcam is not installed. Run: pip install -r requirements.txt")
        print("    (pyvirtualcam needs Python 3.10–3.14 on Windows)")
        sys.exit(1)

    order = BACKENDS if cfg.backend == "auto" else [cfg.backend]
    errors = []
    for backend in order:
        try:
            cam = pyvirtualcam.Camera(
                width=cfg.width, height=cfg.height, fps=cfg.fps,
                fmt=pyvirtualcam.PixelFormat.BGR, backend=backend,
            )
            print(f"[✓] Virtual camera: {cam.device}")
            return cam
        except Exception as e:
            errors.append(f"{backend}: {e}")

    print("[✗] Could not open a virtual camera:")
    for err in errors:
        print(f"      {err}")
    print("    Install OBS Studio (https://obsproject.com) or Unity Capture")
    print("    (https://github.com/schellingb/UnityCapture). If OBS is open with its")
    print("    own Virtual Camera started, stop it first.")
    sys.exit(1)


def frame_worker(cfg: Config, cam, slot: FrameSlot, stop: threading.Event) -> None:
    """Decode the newest frame, fit it, send it to the virtual camera."""
    placeholder = make_placeholder(cfg.width, cfg.height, "Waiting for phone...")
    last_frame = 0.0
    last_placeholder = 0.0
    processed = 0
    report_at = time.monotonic() + 10

    while not stop.is_set():
        data = slot.take(timeout=0.5)
        now = time.monotonic()

        if data is None:
            # Keep feeding a still image so apps show something sensible
            # instead of a frozen last frame.
            if now - last_frame > IDLE_SECONDS and now - last_placeholder > 0.5:
                cam.send(placeholder)
                last_placeholder = now
            continue

        frame = decode_jpeg(data)
        if frame is None:
            continue
        try:
            cam.send(fit_frame(frame, cfg.width, cfg.height, cfg.fit))
        except Exception as e:
            print(f"[!] Virtual camera error: {e}")
            continue
        last_frame = now
        processed += 1

        if now >= report_at:
            print(f"[i] {processed / 10:.1f} FPS to virtual camera, "
                  f"{slot.dropped} dropped (last 10 s)")
            processed, slot.dropped = 0, 0
            report_at = now + 10


# ---------------------------------------------------------------------------
# Web pages
# ---------------------------------------------------------------------------
PAGE_STYLE = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; background: #0f0f0f;
       color: #e0e0e0; min-height: 100vh; display: flex; flex-direction: column;
       align-items: center; justify-content: center; padding: 16px; gap: 12px; }
h1 { font-size: 1.3rem; color: #7ec8e3; }
a { color: #7ec8e3; }
p, li { line-height: 1.5; font-size: 0.95rem; }
.card { max-width: 560px; width: 100%; background: #1a1a1a; border-radius: 12px; padding: 16px 20px; }
.card ol { padding-left: 1.2rem; display: grid; gap: 8px; margin-top: 8px; }
.btn { display: inline-block; padding: 10px 18px; border-radius: 8px; border: 0; background: #2196f3;
       color: #fff; font-size: 0.95rem; text-decoration: none; cursor: pointer; }
"""

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0f0f0f">
<title>Camera Bridge</title>
<style>
{{ style|safe }}
#status { font-size: 0.85rem; padding: 4px 12px; border-radius: 12px; }
#status.connected    { background: #1b5e20; color: #a5d6a7; }
#status.disconnected { background: #b71c1c; color: #ef9a9a; }
#status.waiting      { background: #e65100; color: #ffcc80; }
#error { display: none; background: #b71c1c; color: #fff; padding: 14px 18px; border-radius: 12px;
         max-width: 560px; width: 100%; font-size: 0.85rem; line-height: 1.5; }
#preview { position: relative; width: 100%; max-width: 640px; aspect-ratio: {{ cfg.width }} / {{ cfg.height }};
           background: #000; border-radius: 12px; overflow: hidden; }
video { width: 100%; height: 100%; object-fit: {{ 'contain' if cfg.fit == 'pad' else 'cover' }}; }
canvas { display: none; }
#fps { position: absolute; top: 8px; right: 10px; font-size: 0.75rem; background: rgba(0,0,0,.55);
       padding: 2px 8px; border-radius: 6px; color: #7ec8e3; }
.controls { display: flex; gap: 8px; flex-wrap: wrap; justify-content: center; }
button { padding: 10px 18px; border: none; border-radius: 8px; font-size: 0.95rem; color: #fff; cursor: pointer; }
#btn-start { background: #2196f3; } #btn-stop { background: #616161; } #btn-flip { background: #00897b; }
small { color: #888; text-align: center; max-width: 560px; }
</style>
</head>
<body>
<h1>📷 Camera Bridge</h1>
<div id="status" class="waiting">Connecting…</div>
<div id="error"></div>
<div id="preview">
  <video id="video" autoplay playsinline muted></video>
  <div id="fps">0 FPS</div>
</div>
<canvas id="canvas"></canvas>
<div class="controls">
  <button id="btn-start">Start</button>
  <button id="btn-stop">Stop</button>
  <button id="btn-flip">Flip camera</button>
</div>
<small>Keep this page open and the screen on while you are in a meeting.
{% if https %}<br><a id="setup-link" href="#">Remove the certificate warning</a>{% endif %}</small>

<script>
'use strict';
const CFG = {{ cfg_json|safe }};
const TOKEN = new URLSearchParams(location.search).get('t') || '';
const MAX_IN_FLIGHT = 2;               // frames sent but not yet confirmed by the PC
const TARGET_INTERVAL = 1000 / CFG.fps;

const video = document.getElementById('video');
const canvas = document.getElementById('canvas');
const ctx = canvas.getContext('2d');
const statusEl = document.getElementById('status');
const fpsEl = document.getElementById('fps');
const errorEl = document.getElementById('error');
const setupLink = document.getElementById('setup-link');
if (setupLink) setupLink.href = '/setup?t=' + encodeURIComponent(TOKEN);

let ws = null, wsReady = false, inFlight = 0, replaced = false;
let backoff = 500, reconnectTimer = null, heartbeat = null;
let stream = null, streaming = false, encoding = false, useFront = false;
let lastSent = 0, confirmed = 0, fpsSince = performance.now();
let wakeLock = null;

function setStatus(cls, text) { statusEl.className = cls; statusEl.textContent = text; }

function showError(title, detail) {
  errorEl.replaceChildren();
  const b = document.createElement('strong');
  b.textContent = title;
  errorEl.append(b, document.createElement('br'), document.createTextNode(detail));
  errorEl.style.display = 'block';
}
function hideError() { errorEl.style.display = 'none'; }

// ----- Connection to the PC -------------------------------------------------
function connect() {
  clearTimeout(reconnectTimer);
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + location.host + '/ws?t=' + encodeURIComponent(TOKEN));
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => {
    clearInterval(heartbeat);
    heartbeat = setInterval(() => { if (wsReady) ws.send('p'); }, 5000);
    wsReady = true; inFlight = 0; backoff = 500;
    setStatus('connected', 'Connected to PC');
  };
  ws.onmessage = (e) => {
    if (e.data === 'k') {
      inFlight = Math.max(0, inFlight - 1);
      confirmed++;
      const now = performance.now();
      if (now - fpsSince >= 1000) {
        fpsEl.textContent = Math.round(confirmed * 1000 / (now - fpsSince)) + ' FPS';
        confirmed = 0; fpsSince = now;
      }
    }
  };
  ws.onclose = (e) => {
    wsReady = false; inFlight = 0;
    clearInterval(heartbeat);
    if (e.code === 4001) {
      replaced = true;
      stopCamera();
      setStatus('disconnected', 'Another device took over');
      showError('Streaming stopped', 'Another device connected to the PC. Tap Start to take over again.');
      return;
    }
    if (e.code === 4003) {
      setStatus('disconnected', 'Access denied');
      showError('Access denied', 'This link is not valid any more. Scan the QR code shown on the PC again.');
      return;
    }
    setStatus('waiting', 'Reconnecting…');
    reconnectTimer = setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 5000);
  };
}

// ----- Screen wake lock -----------------------------------------------------
async function keepScreenOn() {
  if (!('wakeLock' in navigator) || wakeLock) return;
  try {
    wakeLock = await navigator.wakeLock.request('screen');
    wakeLock.addEventListener('release', () => { wakeLock = null; });
  } catch (e) { /* not allowed right now; retried when the page is visible again */ }
}
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && streaming) keepScreenOn();
});

// ----- Camera ---------------------------------------------------------------
function sizeCanvas() {
  const vw = video.videoWidth, vh = video.videoHeight;
  if (!vw || !vh) return;
  // Never send more pixels than the PC will use.
  const fitScale = CFG.fit === 'pad'
    ? Math.min(CFG.width / vw, CFG.height / vh)
    : Math.max(CFG.width / vw, CFG.height / vh);
  const scale = Math.min(1, fitScale);
  canvas.width = Math.round(vw * scale);
  canvas.height = Math.round(vh * scale);
}
video.addEventListener('resize', sizeCanvas);   // fires when the phone rotates

async function startCamera() {
  stopCamera();
  hideError();
  if (replaced) { replaced = false; connect(); }

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showError('Camera blocked',
      location.protocol === 'http:'
        ? 'The browser only allows the camera on HTTPS pages. Start the PC script without --no-ssl and open the https:// link.'
        : 'This browser cannot access the camera. Use Chrome.');
    return;
  }
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: useFront ? 'user' : { ideal: 'environment' },
        width: { ideal: Math.max(CFG.width, CFG.height) },
        height: { ideal: Math.min(CFG.width, CFG.height) },
        frameRate: { ideal: CFG.fps },
      },
      audio: false,
    });
  } catch (err) {
    showError('Camera error', err.message + ' Make sure camera permission is granted for this page.');
    return;
  }
  video.srcObject = stream;
  await video.play().catch(() => {});
  sizeCanvas();
  streaming = true;
  keepScreenOn();
  scheduleFrame();
}

function stopCamera() {
  streaming = false;
  if (stream) { stream.getTracks().forEach(t => t.stop()); stream = null; }
  if (wakeLock) { wakeLock.release().catch(() => {}); wakeLock = null; }
}

// ----- Capture loop -----------------------------------------------------------
const hasVideoFrameCallback = 'requestVideoFrameCallback' in HTMLVideoElement.prototype;

function scheduleFrame() {
  if (!streaming) return;
  if (hasVideoFrameCallback) video.requestVideoFrameCallback(onFrame);
  else requestAnimationFrame(onFrame);
}

function onFrame(now) {
  if (!streaming) return;
  scheduleFrame();
  if (now - lastSent < TARGET_INTERVAL * 0.85) return;
  // Back-pressure: wait for the PC to confirm frames, so a slow network
  // drops frames instead of building up delay.
  if (!wsReady || encoding || inFlight >= MAX_IN_FLIGHT || !canvas.width) return;
  lastSent = now;
  encoding = true;
  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
  canvas.toBlob((blob) => {
    encoding = false;
    if (!blob || !wsReady || !streaming) return;
    inFlight++;
    ws.send(blob);
  }, 'image/jpeg', CFG.quality);
}

// ----- Buttons ----------------------------------------------------------------
document.getElementById('btn-start').addEventListener('click', startCamera);
document.getElementById('btn-stop').addEventListener('click', stopCamera);
document.getElementById('btn-flip').addEventListener('click', () => {
  useFront = !useFront;
  if (streaming) startCamera();
});

connect();
startCamera();
</script>
</body>
</html>
"""

SETUP_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Camera Bridge setup</title>
<style>{{ style|safe }}</style>
</head>
<body>
<h1>Remove the certificate warning</h1>
<div class="card">
  <p>Install your PC's personal certificate on this phone once. After that Chrome trusts
  this page without a warning, even if your PC's IP address changes.</p>
  <ol>
    <li>Tap <a class="btn" href="/ca.crt">Download certificate</a></li>
    <li>Open <b>Settings → Security &amp; privacy → More security settings →
      Encryption &amp; credentials → Install a certificate → CA certificate</b>
      (the names vary a little between phones; search Settings for “CA certificate”).</li>
    <li>Tap <b>Install anyway</b>, unlock the phone if asked, and pick the downloaded file
      <code>camera-bridge-ca.crt</code>.</li>
    <li>Close Chrome completely and open the Camera Bridge link again.</li>
  </ol>
</div>
<div class="card">
  <p>This certificate can only vouch for addresses on private networks (such as
  192.168.x.x), so it cannot be used to fake real websites. Android may show
  “Network may be monitored” after installing it; that refers to this certificate.
  To remove it later: <b>Encryption &amp; credentials → User credentials</b>.</p>
</div>
<p><a href="/?t={{ token|urlencode }}">← Back to the camera</a></p>
</body>
</html>
"""

DENIED_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access denied</title><style>{{ style|safe }}</style></head>
<body><h1>Access denied</h1>
<div class="card"><p>This link is missing the access code or it is no longer valid.
Scan the QR code shown in the Camera Bridge window on your PC.</p></div>
</body></html>
"""

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "connect-src 'self'; media-src 'self' blob: mediastream:; img-src 'self' data:; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}


# ---------------------------------------------------------------------------
# Web server
# ---------------------------------------------------------------------------
def create_app(cfg: Config, token: str, slot: FrameSlot) -> Flask:
    app = Flask(__name__)
    # No ping_interval: simple-websocket's ping loop uses select(), which
    # misses data already buffered inside TLS and stalls HTTPS connections.
    # The phone sends a heartbeat instead (see HEARTBEAT_TIMEOUT).
    app.config["SOCK_SERVER_OPTIONS"] = {"max_message_size": WS_MAX_MESSAGE}
    sock = Sock(app)

    active_lock = threading.Lock()
    active = {"ws": None, "peer": None}

    @app.after_request
    def add_headers(resp: Response) -> Response:
        resp.headers.update(SECURITY_HEADERS)
        return resp

    @app.route("/")
    def index():
        if not token_ok(request.args.get("t"), token):
            print(f"[!] Rejected page request without a valid token from {request.remote_addr}")
            return render_template_string(DENIED_HTML, style=PAGE_STYLE), 403
        cfg_json = {
            "width": cfg.width, "height": cfg.height, "fps": cfg.fps,
            "quality": cfg.quality, "fit": cfg.fit,
        }
        return render_template_string(
            INDEX_HTML, style=PAGE_STYLE, cfg=cfg,
            cfg_json=json.dumps(cfg_json), https=cfg.use_ssl,
        )

    @app.route("/setup")
    def setup():
        if not cfg.use_ssl:
            abort(404)
        return render_template_string(SETUP_HTML, style=PAGE_STYLE, token=request.args.get("t", ""))

    @app.route("/ca.crt")
    def ca_cert():
        # The CA *certificate* is public information; its private key never
        # leaves the PC.
        if not cfg.use_ssl or not CA_CERT_FILE.exists():
            abort(404)
        return Response(
            CA_CERT_FILE.read_bytes(),
            mimetype="application/x-x509-ca-cert",
            headers={"Content-Disposition": 'attachment; filename="camera-bridge-ca.crt"'},
        )

    @app.route("/favicon.ico")
    def favicon():
        return Response(status=204)

    @sock.route("/ws")
    def video_socket(ws):
        peer = request.remote_addr
        origin = request.headers.get("Origin")
        if not token_ok(request.args.get("t"), token) or (
            origin and urlparse(origin).netloc != request.host
        ):
            print(f"[!] Rejected video connection from {peer}")
            ws.close(reason=4003, message="access denied")
            return

        with active_lock:
            previous = active["ws"]
            active["ws"], active["peer"] = ws, peer
        if previous is not None:
            print("[i] New phone connection replaces the previous one")
            try:
                previous.close(reason=4001, message="replaced by another device")
            except Exception:
                pass
        print(f"[✓] Phone connected ({peer})")

        try:
            while True:
                data = ws.receive(timeout=HEARTBEAT_TIMEOUT)
                if data is None:
                    print(f"[i] Phone stopped responding ({peer})")
                    break
                if isinstance(data, (bytes, bytearray)):
                    slot.put(bytes(data))
                    ws.send("k")   # confirmation, drives the phone's back-pressure
        except Exception:
            pass   # connection closed
        finally:
            with active_lock:
                if active["ws"] is ws:
                    active["ws"] = active["peer"] = None
                    print(f"[i] Phone disconnected ({peer})")

    return app


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
def parse_args(argv: list[str] | None = None) -> Config:
    p = argparse.ArgumentParser(description="Camera Bridge: use your Android phone as a Windows webcam.")
    p.add_argument("--width", type=int, default=1280, help="virtual camera width (default 1280)")
    p.add_argument("--height", type=int, default=720, help="virtual camera height (default 720)")
    p.add_argument("--fps", type=int, default=30, help="frames per second (default 30)")
    p.add_argument("--quality", type=float, default=0.8,
                   help="JPEG quality sent by the phone, 0.1–1.0 (default 0.8)")
    p.add_argument("--fit", choices=["pad", "crop"], default="pad",
                   help="pad: show the whole picture with black bars (default); "
                        "crop: fill the frame and cut the edges")
    p.add_argument("--port", type=int, default=5000, help="server port (default 5000)")
    p.add_argument("--host", default="0.0.0.0",
                   help="address to listen on (default 0.0.0.0 = all networks)")
    p.add_argument("--backend", choices=["auto", *BACKENDS], default="auto",
                   help="virtual camera driver (default auto)")
    p.add_argument("--new-token", action="store_true",
                   help="create a new access token; old links and QR codes stop working")
    p.add_argument("--no-ssl", action="store_true",
                   help="plain HTTP (not recommended: the phone camera needs HTTPS)")
    p.add_argument("--dry-run", action="store_true",
                   help="test the phone connection without opening a virtual camera")
    a = p.parse_args(argv)
    if not 0.1 <= a.quality <= 1.0:
        p.error("--quality must be between 0.1 and 1.0")
    if a.width < 16 or a.height < 16 or not 1 <= a.fps <= 60:
        p.error("invalid --width/--height/--fps")
    return Config(
        width=a.width, height=a.height, fps=a.fps, quality=a.quality, fit=a.fit,
        port=a.port, host=a.host, use_ssl=not a.no_ssl, backend=a.backend,
        dry_run=a.dry_run, new_token=a.new_token,
    )


def print_connect_info(cfg: Config, ips: list[str], token: str) -> None:
    proto = "https" if cfg.use_ssl else "http"
    urls = [f"{proto}://{ip}:{cfg.port}/?t={token}" for ip in ips]

    print()
    print("=" * 64)
    print("  Scan this QR code with your phone's camera, or open the link:")
    print()
    if segno is not None:
        qr = segno.make(urls[0], error="l")
        try:
            qr.terminal(compact=True, border=2)
        except Exception:
            pass
        try:
            qr.save(QR_FILE, scale=8, border=2)
        except Exception:
            pass
    print(f"  → {urls[0]}")
    for url in urls[1:]:
        print(f"    (other network: {url})")
    if segno is not None and QR_FILE.exists():
        print(f"  QR code image: {QR_FILE}")
    print()
    if cfg.use_ssl:
        print("  First time? Chrome shows a certificate warning: tap Advanced → Proceed,")
        print("  then tap 'Remove the certificate warning' on the page to fix it for good.")
    else:
        print("  WARNING: HTTPS is off. Video is not encrypted and Chrome will block")
        print("  the camera unless you change chrome://flags.")
    print("  Keep the link private: anyone with it can send video to this camera.")
    print("  Press Ctrl+C to stop.")
    print("=" * 64)
    print()


def main(argv: list[str] | None = None) -> None:
    cfg = parse_args(argv)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # don't log URLs with the token

    print("📷 Camera Bridge")
    print(f"   {cfg.width}×{cfg.height} @ {cfg.fps} FPS, fit={cfg.fit}, "
          f"JPEG decoder: {'simplejpeg' if simplejpeg else 'OpenCV'}")

    ips = get_local_ips()
    token = load_or_create_token(cfg.new_token)

    ssl_ctx = None
    if cfg.use_ssl:
        try:
            ensure_certificates(ips)
            ssl_ctx = make_ssl_context()
        except ImportError:
            print("[✗] The 'cryptography' package is required for HTTPS: pip install -r requirements.txt")
            sys.exit(1)

    cam = open_virtual_cam(cfg)
    slot = FrameSlot()
    stop = threading.Event()
    worker = threading.Thread(target=frame_worker, args=(cfg, cam, slot, stop),
                              name="FrameWorker", daemon=True)
    worker.start()

    app = create_app(cfg, token, slot)
    print_connect_info(cfg, ips, token)
    try:
        app.run(host=cfg.host, port=cfg.port, ssl_context=ssl_ctx,
                threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        worker.join(timeout=2)
        cam.close()
        print("[✓] Stopped")


if __name__ == "__main__":
    main()
