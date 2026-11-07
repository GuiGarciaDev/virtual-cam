"""
camera_bridge.py: use your Android phone as a Windows webcam over Wi-Fi.

No app on the phone: it opens a page in Chrome, and the frames end up in a
virtual camera (OBS Virtual Camera or Unity Capture) that Zoom, Teams, Meet,
Discord, etc. can pick.

Security model (see README.md, "Is it safe?"):
  * HTTPS with a certificate signed by a small personal certificate
    authority (CA) that is created once on this PC. Install that CA on the
    phone once and the browser warning is gone for good, even when the PC's
    IP changes. The CA is name-constrained to private network addresses.
  * A secret access token in the URL (shown as a QR code). Pages and video
    connections without it are rejected.
  * Only one phone streams at a time: a new authorised connection replaces
    the previous one.

Resolution, frame rate, image quality and framing can be changed live from
the phone (gear button). Changes are saved for the next start.

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
SETTINGS_FILE = DATA_DIR / "settings.json"
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
SETTINGS_APPLY_TIMEOUT = 8            # seconds to wait for a camera switch

DEFAULT_SETTINGS = {"width": 1280, "height": 720, "fps": 30, "quality": 0.8, "fit": "pad"}

log = logging.getLogger("camera_bridge")


@dataclass
class Config:
    """Startup options that cannot change while running."""
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
# Live settings (resolution, fps, quality, fit)
# ---------------------------------------------------------------------------
def validate_settings(raw: dict) -> dict:
    """Return the valid subset of `raw`; raise ValueError on bad values."""
    out: dict = {}
    if "width" in raw or "height" in raw:
        try:
            w, h = int(raw["width"]), int(raw["height"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("Resolution needs both width and height") from None
        if not (160 <= w <= 3840 and 120 <= h <= 2160) or w % 2 or h % 2:
            raise ValueError(f"Unsupported resolution {w}×{h}")
        out["width"], out["height"] = w, h
    if "fps" in raw:
        try:
            fps = int(raw["fps"])
        except (TypeError, ValueError):
            raise ValueError("Frame rate must be a number") from None
        if not 5 <= fps <= 60:
            raise ValueError("Frame rate must be between 5 and 60")
        out["fps"] = fps
    if "quality" in raw:
        try:
            q = float(raw["quality"])
        except (TypeError, ValueError):
            raise ValueError("Quality must be a number") from None
        if not 0.3 <= q <= 1.0:
            raise ValueError("Quality must be between 0.3 and 1.0")
        out["quality"] = round(q, 2)
    if "fit" in raw:
        if raw["fit"] not in ("pad", "crop"):
            raise ValueError("Framing must be 'pad' or 'crop'")
        out["fit"] = raw["fit"]
    return out


def load_saved_settings() -> dict:
    try:
        return validate_settings(json.loads(SETTINGS_FILE.read_text(encoding="utf-8")))
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"[!] Ignoring saved settings ({e})")
        return {}


def save_settings(values: dict) -> None:
    try:
        DATA_DIR.mkdir(exist_ok=True)
        SETTINGS_FILE.write_text(json.dumps(values, indent=2), encoding="utf-8")
    except OSError as e:
        print(f"[!] Could not save settings: {e}")


class LiveSettings:
    """Settings that the phone can change while the app runs.

    The web handler requests a change; the frame worker applies it (it owns
    the virtual camera, which must be reopened for a new resolution or frame
    rate) and reports back, possibly reverting on failure.
    """

    def __init__(self, values: dict) -> None:
        self._cond = threading.Condition()
        self._values = dict(values)
        self._version = 0
        self._applied_version = 0
        self._error: str | None = None

    def snapshot(self) -> tuple[dict, int]:
        with self._cond:
            return dict(self._values), self._version

    def request(self, changes: dict) -> int:
        with self._cond:
            self._values.update(changes)
            self._version += 1
            return self._version

    def mark_applied(self, version: int, error: str | None = None, revert: dict | None = None) -> None:
        with self._cond:
            if revert:
                self._values.update(revert)
            self._applied_version = max(self._applied_version, version)
            self._error = error
            self._cond.notify_all()

    def wait_applied(self, version: int, timeout: float) -> tuple[dict, str | None]:
        with self._cond:
            ok = self._cond.wait_for(lambda: self._applied_version >= version, timeout)
            error = self._error if ok else "The camera is taking too long to switch; try again"
            return dict(self._values), error


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

    def wake(self) -> None:
        """Wake the worker without a frame (e.g. to apply new settings)."""
        with self._cond:
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


def make_placeholder(width: int, height: int) -> np.ndarray:
    """Dark card with a camera glyph and 'Waiting for phone...'."""
    img = np.full((height, width, 3), (24, 17, 13), dtype=np.uint8)   # BGR #0d1118
    s = height / 720
    cx, cy = width // 2, int(height * 0.42)
    accent = (255, 140, 108)                                           # BGR #6c8cff
    # camera body + lens
    bw, bh = int(110 * s), int(76 * s)
    cv2.rectangle(img, (cx - bw // 2, cy - bh // 2), (cx + bw // 2, cy + bh // 2),
                  accent, max(2, int(5 * s)), cv2.LINE_AA)
    cv2.circle(img, (cx, cy), int(22 * s), accent, max(2, int(5 * s)), cv2.LINE_AA)
    cv2.rectangle(img, (cx - int(22 * s), cy - bh // 2 - int(14 * s)),
                  (cx + int(22 * s), cy - bh // 2), accent, -1, cv2.LINE_AA)

    font = cv2.FONT_HERSHEY_SIMPLEX
    for text, scale, color, dy in (
        ("Waiting for phone...", 1.1 * s, (240, 234, 232), 110),
        ("Open the Camera Bridge page on your phone", 0.62 * s, (178, 163, 154), 160),
    ):
        thickness = max(1, round(2 * s * scale))
        (tw, th), _ = cv2.getTextSize(text, font, scale, thickness)
        cv2.putText(img, text, ((width - tw) // 2, cy + int(dy * s)), font, scale,
                    color, thickness, cv2.LINE_AA)
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


def make_camera(backend: str, width: int, height: int, fps: int):
    if backend == "dry":
        return DryRunCamera()
    import pyvirtualcam
    return pyvirtualcam.Camera(
        width=width, height=height, fps=fps,
        fmt=pyvirtualcam.PixelFormat.BGR, backend=backend,
    )


def open_virtual_cam(cfg: Config, width: int, height: int, fps: int):
    """Open the virtual camera at startup. Returns (camera, backend name)."""
    if cfg.dry_run:
        return DryRunCamera(), "dry"

    try:
        import pyvirtualcam  # noqa: F401
    except ImportError:
        print("[✗] pyvirtualcam is not installed. Run: pip install -r requirements.txt")
        print("    (pyvirtualcam needs Python 3.10–3.14 on Windows)")
        sys.exit(1)

    order = BACKENDS if cfg.backend == "auto" else [cfg.backend]
    errors = []
    for backend in order:
        try:
            cam = make_camera(backend, width, height, fps)
            print(f"[✓] Virtual camera: {cam.device}")
            return cam, backend
        except Exception as e:
            errors.append(f"{backend}: {e}")

    print("[✗] Could not open a virtual camera:")
    for err in errors:
        print(f"      {err}")
    print("    Install OBS Studio (https://obsproject.com) or Unity Capture")
    print("    (https://github.com/schellingb/UnityCapture). If OBS is open with its")
    print("    own Virtual Camera started, stop it first.")
    sys.exit(1)


class CameraHolder:
    """The open virtual camera and the size/fps it was opened with."""

    def __init__(self, cam, backend: str, width: int, height: int, fps: int) -> None:
        self.cam, self.backend = cam, backend
        self.width, self.height, self.fps = width, height, fps

    def params(self) -> tuple[int, int, int]:
        return self.width, self.height, self.fps

    def reopen(self, width: int, height: int, fps: int) -> None:
        """Switch to a new size/fps; on failure restore the old camera and raise."""
        old = self.params()
        self.cam.close()
        try:
            self.cam = make_camera(self.backend, width, height, fps)
        except Exception:
            self.cam = make_camera(self.backend, *old)
            raise
        self.width, self.height, self.fps = width, height, fps

    def close(self) -> None:
        try:
            self.cam.close()
        except Exception:
            pass


def frame_worker(settings: LiveSettings, holder: CameraHolder, slot: FrameSlot,
                 stop: threading.Event) -> None:
    """Decode the newest frame, fit it, send it to the virtual camera.
    Also applies settings changes requested from the phone."""
    placeholder = make_placeholder(holder.width, holder.height)
    applied_version = -1   # check the camera against the settings on the first pass
    last_frame = 0.0
    last_placeholder = 0.0
    processed = 0
    report_at = time.monotonic() + 10

    while not stop.is_set():
        values, version = settings.snapshot()
        if version != applied_version:
            wanted = (values["width"], values["height"], values["fps"])
            error = revert = None
            if wanted != holder.params():
                old = holder.params()
                try:
                    holder.reopen(*wanted)
                    placeholder = make_placeholder(holder.width, holder.height)
                    print(f"[✓] Camera switched to {wanted[0]}×{wanted[1]} @ {wanted[2]} FPS")
                except Exception as e:
                    error = f"Could not switch to {wanted[0]}×{wanted[1]} @ {wanted[2]} FPS: {e}"
                    revert = {"width": old[0], "height": old[1], "fps": old[2]}
                    print(f"[!] {error}")
            settings.mark_applied(version, error, revert)
            applied_version = version
            values, _ = settings.snapshot()

        data = slot.take(timeout=0.5)
        now = time.monotonic()

        if data is None:
            # Keep feeding a still image so apps show something sensible
            # instead of a frozen last frame.
            if now - last_frame > IDLE_SECONDS and now - last_placeholder > 0.5:
                holder.cam.send(placeholder)
                last_placeholder = now
            continue

        frame = decode_jpeg(data)
        if frame is None:
            continue
        try:
            holder.cam.send(fit_frame(frame, holder.width, holder.height, values["fit"]))
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
BASE_STYLE = """
:root {
  color-scheme: dark;
  --bg: #0b0e14;
  --bg-2: #121722;
  --surface: rgba(255, 255, 255, 0.055);
  --surface-2: rgba(255, 255, 255, 0.09);
  --border: rgba(255, 255, 255, 0.08);
  --text: #eef1f6;
  --muted: #98a2b3;
  --accent: #6c8cff;
  --accent-2: #8f6cff;
  --accent-soft: rgba(108, 140, 255, 0.16);
  --ok: #34d399;
  --warn: #fbbf24;
  --bad: #f87171;
  --radius: 20px;
  --font: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
* { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
html, body { height: 100%; }
body {
  font-family: var(--font); color: var(--text); line-height: 1.45;
  background:
    radial-gradient(1200px 600px at 10% -10%, rgba(108,140,255,.18), transparent 60%),
    radial-gradient(900px 500px at 110% 110%, rgba(143,108,255,.14), transparent 60%),
    var(--bg);
  background-attachment: fixed;
}
a { color: var(--accent); text-decoration: none; }
code { font-family: ui-monospace, Consolas, monospace; font-size: .9em; background: var(--surface-2);
       padding: 1px 6px; border-radius: 6px; }
.icon { width: 22px; height: 22px; fill: none; stroke: currentColor; stroke-width: 2;
        stroke-linecap: round; stroke-linejoin: round; flex: none; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 650; letter-spacing: -.01em; }
.logo { width: 34px; height: 34px; border-radius: 10px; display: grid; place-items: center;
        background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: #fff;
        box-shadow: 0 6px 20px rgba(108,140,255,.35); }
.logo .icon { width: 19px; height: 19px; }
.btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px;
       padding: 12px 20px; border-radius: 14px; border: 0; font: inherit; font-weight: 600;
       color: #fff; background: linear-gradient(135deg, var(--accent), var(--accent-2));
       cursor: pointer; box-shadow: 0 8px 24px rgba(108,140,255,.3); }
.btn.secondary { background: var(--surface-2); box-shadow: none; color: var(--text);
                 border: 1px solid var(--border); }
.page { min-height: 100dvh; display: flex; flex-direction: column; align-items: center;
        padding: max(20px, env(safe-area-inset-top)) 16px max(24px, env(safe-area-inset-bottom)); gap: 18px; }
.page > * { width: 100%; max-width: 560px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
        padding: 20px; backdrop-filter: blur(12px); }
.card h1 { font-size: 1.35rem; letter-spacing: -.02em; margin-bottom: 6px; }
.card p { color: var(--muted); }
.steps { list-style: none; counter-reset: step; display: grid; gap: 14px; margin-top: 16px; }
.steps li { counter-increment: step; display: grid; grid-template-columns: 30px 1fr; gap: 12px; align-items: start; }
.steps li::before { content: counter(step); width: 30px; height: 30px; border-radius: 50%;
        display: grid; place-items: center; font-weight: 700; font-size: .9rem;
        background: var(--accent-soft); color: var(--accent); }
"""

ICONS = {
    "camera": '<path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2"/>',
    "flip": '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>'
            '<path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83'
                'l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4'
                'a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1'
                'H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06'
                'A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33'
                'l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09'
                'a1.65 1.65 0 0 0-1.51 1z"/>',
    "stop": '<rect x="6" y="6" width="12" height="12" rx="2"/>',
    "play": '<polygon points="6 4 20 12 6 20 6 4"/>',
    "close": '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>',
    "lock": '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/>'
                '<line x1="12" y1="15" x2="12" y2="3"/>',
    "back": '<polyline points="15 18 9 12 15 6"/>',
}


def icon(name: str) -> str:
    return f'<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">{ICONS[name]}</svg>'


INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0b0e14">
<title>Camera Bridge</title>
<style>
{{ base_style|safe }}
body { overflow: hidden; }
.app { height: 100dvh; display: flex; flex-direction: column; gap: 14px;
       padding: max(14px, env(safe-area-inset-top)) 16px max(16px, env(safe-area-inset-bottom)); }

/* Top bar */
.topbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.pill { display: inline-flex; align-items: center; gap: 8px; padding: 7px 12px 7px 10px; border-radius: 999px;
        background: var(--surface); border: 1px solid var(--border); font-size: .82rem; font-weight: 600;
        white-space: nowrap; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--warn); box-shadow: 0 0 0 4px rgba(251,191,36,.15); }
.pill.ok .dot { background: var(--ok); box-shadow: 0 0 0 4px rgba(52,211,153,.18); animation: pulse 2s infinite; }
.pill.bad .dot { background: var(--bad); box-shadow: 0 0 0 4px rgba(248,113,113,.18); }
@keyframes pulse { 50% { box-shadow: 0 0 0 7px rgba(52,211,153,0); } }

/* Preview */
.stage { flex: 1; min-height: 0; display: grid; place-items: center; }
.preview { --ar: 1.7778; position: relative; overflow: hidden; border-radius: 24px; background: #000;
           width: min(100%, calc((100dvh - 210px) * var(--ar))); aspect-ratio: var(--ar);
           border: 1px solid var(--border);
           box-shadow: 0 30px 80px rgba(0,0,0,.55), 0 0 0 1px rgba(255,255,255,.02) inset;
           transition: aspect-ratio .3s ease; }
/* No live picture yet: use a taller card so messages fit on portrait phones */
.preview.idle { aspect-ratio: auto; width: 100%; height: min(440px, 100%); }
.preview.idle .hud { display: none; }
.preview video { width: 100%; height: 100%; object-fit: contain; display: block; }
.preview.fill video { object-fit: cover; }
.hud { position: absolute; inset: 12px 12px auto 12px; display: flex; justify-content: space-between;
       gap: 8px; pointer-events: none; }
.chip { padding: 5px 10px; border-radius: 999px; font-size: .74rem; font-weight: 650; letter-spacing: .02em;
        background: rgba(10,12,18,.55); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,.08); }
.chip.live { color: #fff; background: rgba(239,68,68,.85); border-color: transparent; display: none; }
.preview.live .chip.live { display: inline-block; }
.overlay { position: absolute; inset: 0; display: grid; place-items: center; text-align: center; padding: 24px;
           background: radial-gradient(circle at 50% 40%, rgba(108,140,255,.16), rgba(5,7,12,.92) 70%); }
.overlay[hidden] { display: none; }
.overlay .big { width: 64px; height: 64px; border-radius: 20px; display: grid; place-items: center; margin: 0 auto 14px;
                background: var(--accent-soft); color: var(--accent); }
.overlay .big .icon { width: 30px; height: 30px; }
.overlay h2 { font-size: 1.1rem; margin-bottom: 6px; }
.overlay p { color: var(--muted); font-size: .9rem; max-width: 320px; margin: 0 auto 16px; }

/* Bottom dock */
.dock { display: flex; align-items: center; justify-content: center; gap: 18px; }
.round { width: 54px; height: 54px; border-radius: 50%; border: 1px solid var(--border); display: grid; place-items: center;
         background: var(--surface); color: var(--text); cursor: pointer; transition: transform .15s, background .2s; }
.round:active, .main:active { transform: scale(.94); }
.main { min-width: 150px; height: 60px; border-radius: 999px; border: 0; display: inline-flex; align-items: center;
        justify-content: center; gap: 10px; font: inherit; font-weight: 700; font-size: 1rem; color: #fff; cursor: pointer;
        background: linear-gradient(135deg, var(--accent), var(--accent-2));
        box-shadow: 0 10px 30px rgba(108,140,255,.35); transition: transform .15s, background .3s, box-shadow .3s; }
.main > span { display: inline-flex; align-items: center; }
.main.stop { background: linear-gradient(135deg, #ef4444, #f97316); box-shadow: 0 10px 30px rgba(239,68,68,.32); }

/* Settings sheet */
.backdrop { position: fixed; inset: 0; background: rgba(3,5,10,.55); backdrop-filter: blur(3px);
            opacity: 0; pointer-events: none; transition: opacity .25s; z-index: 10; }
.sheet { position: fixed; left: 0; right: 0; bottom: 0; margin: 0 auto; max-width: 560px; z-index: 11;
         background: linear-gradient(180deg, #161c29, #10141d); border: 1px solid var(--border); border-bottom: 0;
         border-radius: 28px 28px 0 0; padding: 10px 20px max(22px, env(safe-area-inset-bottom));
         transform: translateY(105%); transition: transform .32s cubic-bezier(.2,.8,.2,1);
         max-height: 88dvh; overflow-y: auto; box-shadow: 0 -20px 60px rgba(0,0,0,.5); }
body.sheet-open .backdrop { opacity: 1; pointer-events: auto; }
body.sheet-open .sheet { transform: none; }
.grabber { width: 42px; height: 5px; border-radius: 3px; background: rgba(255,255,255,.18); margin: 0 auto 14px; }
.sheet-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
.sheet-head h2 { font-size: 1.15rem; letter-spacing: -.01em; }
.icon-btn { width: 38px; height: 38px; border-radius: 50%; border: 0; background: var(--surface-2); color: var(--text);
            display: grid; place-items: center; cursor: pointer; }
.icon-btn .icon { width: 18px; height: 18px; }
.field { padding: 16px 0; border-bottom: 1px solid var(--border); }
.field:last-of-type { border-bottom: 0; }
.label { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 10px; }
.label span:first-child { font-weight: 650; }
.label small, .value { color: var(--muted); font-size: .82rem; }
.value { font-weight: 650; color: var(--accent); }
.segmented { display: grid; grid-auto-flow: column; grid-auto-columns: 1fr; gap: 4px; padding: 4px;
             background: rgba(0,0,0,.28); border: 1px solid var(--border); border-radius: 14px; }
.segmented button { border: 0; border-radius: 10px; padding: 10px 6px; background: transparent; color: var(--muted);
                    font: inherit; font-weight: 650; font-size: .9rem; cursor: pointer; transition: background .2s, color .2s; }
.segmented button small { display: block; font-size: .7rem; font-weight: 500; opacity: .8; }
.segmented button.active { background: var(--accent); color: #fff; box-shadow: 0 4px 14px rgba(108,140,255,.35); }
input[type=range] { width: 100%; height: 30px; -webkit-appearance: none; appearance: none; background: transparent; }
input[type=range]::-webkit-slider-runnable-track { height: 6px; border-radius: 3px;
  background: linear-gradient(90deg, var(--accent) var(--fill, 50%), rgba(255,255,255,.12) var(--fill, 50%)); }
input[type=range]::-webkit-slider-thumb { -webkit-appearance: none; width: 24px; height: 24px; margin-top: -9px;
  border-radius: 50%; background: #fff; box-shadow: 0 2px 10px rgba(0,0,0,.4); }
.hint { color: var(--muted); font-size: .8rem; margin-top: 4px; }
.sheet.busy .field { opacity: .55; pointer-events: none; }
.link-row { display: flex; align-items: center; gap: 12px; margin-top: 14px; padding: 14px; border-radius: 16px;
            background: var(--surface); border: 1px solid var(--border); color: var(--text); }
.link-row .icon { color: var(--ok); }
.link-row small { display: block; color: var(--muted); }

/* Toast */
.toast { position: fixed; left: 50%; top: max(16px, env(safe-area-inset-top)); z-index: 20;
         transform: translate(-50%, -150%); opacity: 0; visibility: hidden;
         transition: transform .3s cubic-bezier(.2,.8,.2,1), opacity .3s, visibility .3s;
         padding: 10px 16px; border-radius: 999px; font-size: .88rem; font-weight: 600; max-width: calc(100% - 32px);
         background: rgba(22,28,41,.92); border: 1px solid var(--border); backdrop-filter: blur(12px);
         box-shadow: 0 10px 30px rgba(0,0,0,.4); }
.toast.show { transform: translate(-50%, 0); opacity: 1; visibility: visible; }
.toast.error { border-color: rgba(248,113,113,.5); color: #fecaca; }

@media (orientation: landscape) and (max-height: 520px) {
  .app { flex-direction: row; align-items: stretch; }
  .topbar { display: none; }
  .preview { width: min(100%, calc((100dvh - 40px) * var(--ar))); }
  .dock { flex-direction: column; }
}
</style>
</head>
<body>
<main class="app">
  <header class="topbar">
    <div class="brand"><span class="logo">{{ icons.camera|safe }}</span>Camera Bridge</div>
    <div id="status" class="pill"><span class="dot"></span><span id="status-text">Connecting…</span></div>
  </header>

  <section class="stage">
    <div id="preview" class="preview idle">
      <video id="video" autoplay playsinline muted></video>
      <div class="hud">
        <span class="chip live">LIVE</span>
        <span style="display:flex;gap:6px;margin-left:auto">
          <span id="res-chip" class="chip">720p</span>
          <span id="fps-chip" class="chip">0 fps</span>
        </span>
      </div>
      <div id="overlay" class="overlay">
        <div>
          <div class="big">{{ icons.camera|safe }}</div>
          <h2 id="ov-title">Starting camera…</h2>
          <p id="ov-text">Allow camera access when Chrome asks.</p>
          <button id="ov-action" class="btn" hidden></button>
        </div>
      </div>
    </div>
  </section>

  <nav class="dock">
    <button id="btn-flip" class="round" aria-label="Switch between front and back camera">{{ icons.flip|safe }}</button>
    <button id="btn-toggle" class="main"><span id="toggle-icon">{{ icons.play|safe }}</span><span id="toggle-text">Start</span></button>
    <button id="btn-settings" class="round" aria-label="Settings">{{ icons.settings|safe }}</button>
  </nav>
</main>

<div id="backdrop" class="backdrop"></div>
<aside id="sheet" class="sheet" role="dialog" aria-modal="true" aria-labelledby="sheet-title">
  <div class="grabber"></div>
  <div class="sheet-head">
    <h2 id="sheet-title">Settings</h2>
    <button id="sheet-close" class="icon-btn" aria-label="Close settings">{{ icons.close|safe }}</button>
  </div>

  <div class="field">
    <div class="label"><span>Resolution</span><small>Webcam size on the PC</small></div>
    <div class="segmented" data-setting="resolution">
      <button data-value="854x480">480p<small>SD</small></button>
      <button data-value="1280x720">720p<small>HD</small></button>
      <button data-value="1920x1080">1080p<small>Full HD</small></button>
    </div>
  </div>

  <div class="field">
    <div class="label"><span>Frame rate</span><small>Lower is lighter on Wi-Fi</small></div>
    <div class="segmented" data-setting="fps">
      <button data-value="15">15<small>fps</small></button>
      <button data-value="24">24<small>fps</small></button>
      <button data-value="30">30<small>fps</small></button>
    </div>
  </div>

  <div class="field">
    <div class="label"><span>Image quality</span><span id="quality-value" class="value">80%</span></div>
    <input id="quality" type="range" min="40" max="95" step="5" value="80" aria-label="Image quality">
    <p class="hint">Lower it if the picture stutters.</p>
  </div>

  <div class="field">
    <div class="label"><span>Framing</span><small>When the phone is held upright</small></div>
    <div class="segmented" data-setting="fit">
      <button data-value="pad">Fit<small>whole picture</small></button>
      <button data-value="crop">Fill<small>crop edges</small></button>
    </div>
  </div>

  <p class="hint">Changes apply right away and are remembered. If your meeting app shows a stretched or frozen
    picture after changing the resolution, pick the camera again in the app.</p>

  {% if https %}
  <a id="setup-link" class="link-row" href="#">{{ icons.shield|safe }}
    <span>Remove the security warning<small>Install this PC's certificate once</small></span></a>
  {% endif %}
</aside>

<div id="toast" class="toast" role="status" aria-live="polite"></div>

<script>
'use strict';
let S = {{ settings_json|safe }};                // live settings, kept in sync with the PC
const ICON = {{ icons_json|safe }};
const TOKEN = new URLSearchParams(location.search).get('t') || '';
const MAX_IN_FLIGHT = 2;                          // frames sent but not yet confirmed by the PC

const $ = (id) => document.getElementById(id);
const video = $('video'), preview = $('preview');
const canvas = document.createElement('canvas');
const ctx = canvas.getContext('2d');
if ($('setup-link')) $('setup-link').href = '/setup?t=' + encodeURIComponent(TOKEN);

let ws = null, wsReady = false, inFlight = 0, replaced = false, denied = false;
let backoff = 500, reconnectTimer = null, heartbeat = null;
let stream = null, streaming = false, encoding = false, useFront = false;
let lastSent = 0, confirmed = 0, fpsSince = performance.now();
let wakeLock = null, pendingSettings = false;

// ----- Small UI helpers --------------------------------------------------------
function setStatus(kind, text) { $('status').className = 'pill ' + kind; $('status-text').textContent = text; }

let toastTimer = null;
function toast(text, isError) {
  const t = $('toast');
  t.textContent = text;
  t.className = 'toast show' + (isError ? ' error' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = 'toast' + (isError ? ' error' : ''); }, isError ? 4500 : 2200);
}

function showOverlay(title, text, actionLabel, action) {
  $('ov-title').textContent = title;
  $('ov-text').textContent = text;
  const btn = $('ov-action');
  btn.hidden = !actionLabel;
  if (actionLabel) { btn.textContent = actionLabel; btn.onclick = action; }
  $('overlay').hidden = false;
  preview.classList.add('idle');
}
function hideOverlay() { $('overlay').hidden = true; preview.classList.remove('idle'); }

function updateToggle() {
  const b = $('btn-toggle');
  b.classList.toggle('stop', streaming);
  $('toggle-icon').innerHTML = streaming ? ICON.stop : ICON.play;
  $('toggle-text').textContent = streaming ? 'Stop' : 'Start';
  preview.classList.toggle('live', streaming && wsReady);
}

function resLabel(w, h) {
  const named = { '854x480': '480p', '1280x720': '720p', '1920x1080': '1080p' };
  return named[w + 'x' + h] || (w + '×' + h);
}

// Reflect the current settings in the page.
function renderSettings() {
  preview.style.setProperty('--ar', (S.width / S.height).toFixed(4));
  preview.classList.toggle('fill', S.fit === 'crop');
  $('res-chip').textContent = resLabel(S.width, S.height);
  const current = { resolution: S.width + 'x' + S.height, fps: String(S.fps), fit: S.fit };
  document.querySelectorAll('.segmented').forEach(group => {
    group.querySelectorAll('button').forEach(b => {
      b.classList.toggle('active', b.dataset.value === current[group.dataset.setting]);
    });
  });
  const q = Math.round(S.quality * 100);
  $('quality').value = q;
  $('quality-value').textContent = q + '%';
  paintRange($('quality'));
  sizeCanvas();
}
function paintRange(r) {
  const pct = (r.value - r.min) / (r.max - r.min) * 100;
  r.style.setProperty('--fill', pct + '%');
}

// ----- Settings sheet --------------------------------------------------------------
function openSheet() { document.body.classList.add('sheet-open'); }
function closeSheet() { document.body.classList.remove('sheet-open'); }
$('btn-settings').addEventListener('click', openSheet);
$('sheet-close').addEventListener('click', closeSheet);
$('backdrop').addEventListener('click', closeSheet);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeSheet(); });

function requestSettings(changes) {
  if (!wsReady) { toast('Not connected to the PC', true); renderSettings(); return; }
  pendingSettings = true;
  $('sheet').classList.add('busy');
  ws.send(JSON.stringify(Object.assign({ type: 'settings' }, changes)));
}

document.querySelectorAll('.segmented').forEach(group => {
  group.addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b || b.classList.contains('active')) return;
    const v = b.dataset.value, key = group.dataset.setting;
    if (key === 'resolution') {
      const [w, h] = v.split('x').map(Number);
      requestSettings({ width: w, height: h });
    } else if (key === 'fps') {
      requestSettings({ fps: Number(v) });
    } else {
      requestSettings({ fit: v });
    }
  });
});
$('quality').addEventListener('input', (e) => { $('quality-value').textContent = e.target.value + '%'; paintRange(e.target); });
$('quality').addEventListener('change', (e) => requestSettings({ quality: Number(e.target.value) / 100 }));

function onSettingsMessage(msg) {
  const prev = S;
  S = msg.settings;
  const wasRequest = pendingSettings && msg.reason === 'update';
  if (msg.reason === 'update') { pendingSettings = false; $('sheet').classList.remove('busy'); }
  renderSettings();
  if (msg.error) toast(msg.error, true);
  else if (wasRequest) toast('Applied: ' + resLabel(S.width, S.height) + ' · ' + S.fps + ' fps');
  // A new size or frame rate needs the phone camera restarted with new constraints.
  if (streaming && (prev.width !== S.width || prev.height !== S.height || prev.fps !== S.fps)) startCamera();
}

// ----- Connection to the PC ------------------------------------------------------
function connect() {
  clearTimeout(reconnectTimer);
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + location.host + '/ws?t=' + encodeURIComponent(TOKEN));
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => {
    clearInterval(heartbeat);
    heartbeat = setInterval(() => { if (wsReady) ws.send('p'); }, 5000);
    wsReady = true; inFlight = 0; backoff = 500;
    setStatus('ok', 'Connected to PC');
    updateToggle();
  };
  ws.onmessage = (e) => {
    if (e.data === 'k') {
      inFlight = Math.max(0, inFlight - 1);
      confirmed++;
      const now = performance.now();
      if (now - fpsSince >= 1000) {
        $('fps-chip').textContent = Math.round(confirmed * 1000 / (now - fpsSince)) + ' fps';
        confirmed = 0; fpsSince = now;
      }
      return;
    }
    let msg;
    try { msg = JSON.parse(e.data); } catch (_) { return; }
    if (msg.type === 'settings') onSettingsMessage(msg);
  };
  ws.onclose = (e) => {
    wsReady = false; inFlight = 0;
    clearInterval(heartbeat);
    if (pendingSettings) { pendingSettings = false; $('sheet').classList.remove('busy'); }
    updateToggle();
    if (e.code === 4001) {
      replaced = true;
      stopCamera();
      setStatus('bad', 'Disconnected');
      showOverlay('Another device took over', 'Only one phone can stream at a time.', 'Use this phone', startCamera);
      return;
    }
    if (e.code === 4003) {
      denied = true;
      stopCamera();
      setStatus('bad', 'Access denied');
      showOverlay('Access denied', 'This link is no longer valid. Scan the QR code shown on your PC again.');
      return;
    }
    setStatus('', 'Reconnecting…');
    reconnectTimer = setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 5000);
  };
}

// ----- Screen wake lock ----------------------------------------------------------
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

// ----- Camera ----------------------------------------------------------------------
function sizeCanvas() {
  const vw = video.videoWidth, vh = video.videoHeight;
  if (!vw || !vh) return;
  // Never send more pixels than the PC will use.
  const fitScale = S.fit === 'pad' ? Math.min(S.width / vw, S.height / vh) : Math.max(S.width / vw, S.height / vh);
  const scale = Math.min(1, fitScale);
  canvas.width = Math.round(vw * scale);
  canvas.height = Math.round(vh * scale);
}
video.addEventListener('resize', sizeCanvas);   // fires when the phone rotates

async function startCamera() {
  if (denied) return;
  stopCamera(true);
  if (replaced) { replaced = false; connect(); }
  showOverlay('Starting camera…', 'Allow camera access when Chrome asks.');

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showOverlay('Camera blocked',
      location.protocol === 'http:'
        ? 'Chrome only allows the camera on secure pages. Open the https:// link shown on your PC.'
        : 'This browser cannot use the camera. Please open the link in Chrome.');
    return;
  }
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: useFront ? 'user' : { ideal: 'environment' },
        width: { ideal: Math.max(S.width, S.height) },
        height: { ideal: Math.min(S.width, S.height) },
        frameRate: { ideal: S.fps },
      },
      audio: false,
    });
  } catch (err) {
    showOverlay('Camera not available',
      (err && err.name === 'NotAllowedError')
        ? 'Camera permission was denied. Tap the lock icon in the address bar, allow the camera, then try again.'
        : (err && err.message) || 'Could not start the camera.',
      'Try again', startCamera);
    updateToggle();
    return;
  }
  video.srcObject = stream;
  await video.play().catch(() => {});
  sizeCanvas();
  streaming = true;
  hideOverlay();
  updateToggle();
  keepScreenOn();
  scheduleFrame();
}

function stopCamera(silent) {
  streaming = false;
  if (stream) { stream.getTracks().forEach(t => t.stop()); stream = null; }
  if (wakeLock) { wakeLock.release().catch(() => {}); wakeLock = null; }
  updateToggle();
  if (!silent && !replaced && !denied) {
    showOverlay('Camera is off', 'Your PC shows "Waiting for phone" until you start again.', 'Start camera', startCamera);
  }
}

// ----- Capture loop ----------------------------------------------------------------
const hasVideoFrameCallback = 'requestVideoFrameCallback' in HTMLVideoElement.prototype;

function scheduleFrame() {
  if (!streaming) return;
  if (hasVideoFrameCallback) video.requestVideoFrameCallback(onFrame);
  else requestAnimationFrame(onFrame);
}

function onFrame(now) {
  if (!streaming) return;
  scheduleFrame();
  if (now - lastSent < (1000 / S.fps) * 0.85) return;
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
  }, 'image/jpeg', S.quality);
}

// ----- Buttons ---------------------------------------------------------------------
$('btn-toggle').addEventListener('click', () => { streaming ? stopCamera() : startCamera(); });
$('btn-flip').addEventListener('click', () => {
  useFront = !useFront;
  toast(useFront ? 'Front camera' : 'Back camera');
  if (streaming) startCamera();
});

renderSettings();
updateToggle();
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
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0b0e14">
<title>Camera Bridge setup</title>
<style>{{ base_style|safe }}</style>
</head>
<body>
<main class="page">
  <div class="brand"><span class="logo">{{ icons.camera|safe }}</span>Camera Bridge</div>
  <section class="card">
    <h1>Remove the security warning</h1>
    <p>Install your PC's certificate on this phone once. After that Chrome trusts the Camera Bridge
       page without a warning, even if your PC's address changes.</p>
    <ol class="steps">
      <li><div><a class="btn" href="/ca.crt">{{ icons.download|safe }} Download certificate</a></div></li>
      <li><div>Open <b>Settings</b> and search for <b>“CA certificate”</b>. It's usually under
        <b>Security &amp; privacy → More security settings → Encryption &amp; credentials → Install a certificate</b>.</div></li>
      <li><div>Tap <b>CA certificate → Install anyway</b>, unlock the phone if asked, and choose
        <code>camera-bridge-ca.crt</code>.</div></li>
      <li><div>Close Chrome completely and open the Camera Bridge link again.</div></li>
    </ol>
  </section>
  <section class="card">
    <h1 style="font-size:1.05rem">Is this safe?</h1>
    <p>This certificate only works for home-network addresses (like 192.168.x.x), so it can't be used to
       fake real websites. Android may show “Network may be monitored”; that refers to this certificate.
       Remove it any time under <b>Encryption &amp; credentials → User credentials</b>.</p>
  </section>
  <a class="btn secondary" href="/?t={{ token|urlencode }}">{{ icons.back|safe }} Back to the camera</a>
</main>
</body>
</html>
"""

DENIED_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0b0e14">
<title>Access denied</title><style>{{ base_style|safe }}
.page { justify-content: center; }
.card { text-align: center; }
.lock { width: 64px; height: 64px; border-radius: 20px; display: grid; place-items: center; margin: 0 auto 16px;
        background: rgba(248,113,113,.14); color: var(--bad); }
.lock .icon { width: 30px; height: 30px; }
</style></head>
<body><main class="page">
  <section class="card">
    <div class="lock">{{ icons.lock|safe }}</div>
    <h1>Access denied</h1>
    <p>This link is missing its access code, or the code has changed.<br>
       Scan the QR code shown in the Camera Bridge window on your PC.</p>
  </section>
</main></body></html>
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
def create_app(cfg: Config, token: str, slot: FrameSlot, settings: LiveSettings) -> Flask:
    app = Flask(__name__)
    # No ping_interval: simple-websocket's ping loop uses select(), which
    # misses data already buffered inside TLS and stalls HTTPS connections.
    # The phone sends a heartbeat instead (see HEARTBEAT_TIMEOUT).
    app.config["SOCK_SERVER_OPTIONS"] = {"max_message_size": WS_MAX_MESSAGE}
    sock = Sock(app)
    icons = {name: icon(name) for name in ICONS}

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
            return render_template_string(DENIED_HTML, base_style=BASE_STYLE, icons=icons), 403
        values, _ = settings.snapshot()
        return render_template_string(
            INDEX_HTML, base_style=BASE_STYLE, icons=icons,
            icons_json=json.dumps({"play": icons["play"], "stop": icons["stop"]}),
            settings_json=json.dumps(values), https=cfg.use_ssl,
        )

    @app.route("/setup")
    def setup():
        if not cfg.use_ssl:
            abort(404)
        return render_template_string(SETUP_HTML, base_style=BASE_STYLE, icons=icons,
                                      token=request.args.get("t", ""))

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

    def send_settings(ws, reason: str, values: dict, error: str | None = None) -> None:
        ws.send(json.dumps({"type": "settings", "reason": reason, "settings": values, "error": error}))

    def handle_settings(ws, raw: dict) -> None:
        try:
            changes = validate_settings(raw)
        except ValueError as e:
            values, _ = settings.snapshot()
            send_settings(ws, "update", values, str(e))
            return
        version = settings.request(changes)
        slot.wake()
        values, error = settings.wait_applied(version, SETTINGS_APPLY_TIMEOUT)
        if not error:
            save_settings(values)
            print(f"[i] Settings: {values['width']}×{values['height']} @ {values['fps']} FPS, "
                  f"quality {round(values['quality'] * 100)}%, fit={values['fit']}")
        send_settings(ws, "update", values, error)

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
            values, _ = settings.snapshot()
            send_settings(ws, "connect", values)
            while True:
                data = ws.receive(timeout=HEARTBEAT_TIMEOUT)
                if data is None:
                    print(f"[i] Phone stopped responding ({peer})")
                    break
                if isinstance(data, (bytes, bytearray)):
                    slot.put(bytes(data))
                    ws.send("k")   # confirmation, drives the phone's back-pressure
                elif isinstance(data, str) and data.startswith("{"):
                    try:
                        msg = json.loads(data)
                    except ValueError:
                        continue
                    if isinstance(msg, dict) and msg.get("type") == "settings":
                        handle_settings(ws, msg)
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
def parse_args(argv: list[str] | None = None) -> tuple[Config, dict]:
    p = argparse.ArgumentParser(
        description="Camera Bridge: use your Android phone as a Windows webcam.",
        epilog="Resolution, fps, quality and fit can also be changed live from the phone "
               "(gear button); the last values used are remembered.",
    )
    p.add_argument("--width", type=int, help="virtual camera width (default 1280)")
    p.add_argument("--height", type=int, help="virtual camera height (default 720)")
    p.add_argument("--fps", type=int, help="frames per second (default 30)")
    p.add_argument("--quality", type=float,
                   help="JPEG quality sent by the phone, 0.3–1.0 (default 0.8)")
    p.add_argument("--fit", choices=["pad", "crop"],
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

    # Defaults, then the values saved from the phone, then explicit options.
    values = dict(DEFAULT_SETTINGS)
    values.update(load_saved_settings())
    explicit = {k: getattr(a, k) for k in ("width", "height", "fps", "quality", "fit")
                if getattr(a, k) is not None}
    if ("width" in explicit) != ("height" in explicit):
        explicit.setdefault("width", values["width"])
        explicit.setdefault("height", values["height"])
    try:
        values.update(validate_settings(explicit))
    except ValueError as e:
        p.error(str(e))

    cfg = Config(port=a.port, host=a.host, use_ssl=not a.no_ssl, backend=a.backend,
                 dry_run=a.dry_run, new_token=a.new_token)
    return cfg, values


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
        print("  then open Settings (gear) → 'Remove the security warning' to fix it for good.")
    else:
        print("  WARNING: HTTPS is off. Video is not encrypted and Chrome will block")
        print("  the camera unless you change chrome://flags.")
    print("  Keep the link private: anyone with it can send video to this camera.")
    print("  Press Ctrl+C to stop.")
    print("=" * 64)
    print()


def main(argv: list[str] | None = None) -> None:
    cfg, values = parse_args(argv)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # don't log URLs with the token

    print("📷 Camera Bridge")
    print(f"   {values['width']}×{values['height']} @ {values['fps']} FPS, fit={values['fit']}, "
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

    cam, backend = open_virtual_cam(cfg, values["width"], values["height"], values["fps"])
    holder = CameraHolder(cam, backend, values["width"], values["height"], values["fps"])
    settings = LiveSettings(values)
    slot = FrameSlot()
    stop = threading.Event()
    worker = threading.Thread(target=frame_worker, args=(settings, holder, slot, stop),
                              name="FrameWorker", daemon=True)
    worker.start()

    app = create_app(cfg, token, slot, settings)
    print_connect_info(cfg, ips, token)
    try:
        app.run(host=cfg.host, port=cfg.port, ssl_context=ssl_ctx,
                threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        worker.join(timeout=2)
        holder.close()
        print("[✓] Stopped")


if __name__ == "__main__":
    main()
