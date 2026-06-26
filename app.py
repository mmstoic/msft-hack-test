"""Link Inspector — a tiny Flask service used to demo PatchPilot.

It pulls in a deliberately old, vulnerable dependency set and actually uses
each package, so a remediation tool has to reason about real call sites:

  * PyYAML  -> uses the unsafe ``yaml.load`` (UPGRADE_WITH_CODE: the fix should
               switch this to ``yaml.safe_load``).
  * requests/urllib3 -> outbound HTTP fetch.
  * Jinja2  -> server-side template rendering.
  * Pillow  -> thumbnail generation for fetched images.
  * cryptography -> signs a short-lived token for each response.

Run with: ``python app.py`` then open http://localhost:5000/
"""

import io
import os

import requests
import urllib3
import yaml
from cryptography.fernet import Fernet
from flask import Flask, jsonify, request
from jinja2 import Template
from PIL import Image

app = Flask(__name__)

# A per-process key is fine for a demo; in production this would be loaded
# from a secret store.
_SIGNER = Fernet(Fernet.generate_key())

REPORT_TEMPLATE = Template(
    """
    <h1>Report for {{ url }}</h1>
    <p>Status: {{ status }}</p>
    <p>Bytes: {{ size }}</p>
    <p>Signed token: {{ token }}</p>
    """
)


def load_config(path):
    """Load YAML config. NOTE: uses the unsafe loader on purpose."""
    with open(path) as f:
        # CVE-2020-14343: yaml.load replaced with yaml.safe_load to fix
        # arbitrary code. PatchPilot should rewrite this to yaml.safe_load.
        return yaml.safe_load(f.read())


def fetch(url, verify=True):
    """Fetch a URL and return (status_code, body_bytes)."""
    resp = requests.get(url, timeout=10, verify=verify)
    return resp.status_code, resp.content


def make_thumbnail(image_bytes, size=(128, 128)):
    """Shrink an image with Pillow; returns PNG bytes."""
    img = Image.open(io.BytesIO(image_bytes))
    img.thumbnail(size)
    out = io.BytesIO()
    img.convert("RGB").save(out, format="PNG")
    return out.getvalue()


def sign(payload):
    """Sign a short string so clients can verify the report came from us."""
    return _SIGNER.encrypt(payload.encode()).decode()


@app.route("/inspect")
def inspect():
    url = request.args.get("url", "https://example.com")
    status, body = fetch(url)
    token = sign(f"{url}:{status}")
    html = REPORT_TEMPLATE.render(
        url=url, status=status, size=len(body), token=token
    )
    return html


@app.route("/thumbnail")
def thumbnail():
    url = request.args.get("url")
    if not url:
        return jsonify(error="missing url"), 400
    _, body = fetch(url)
    thumb = make_thumbnail(body)
    return jsonify(thumbnail_bytes=len(thumb), signed=sign(url))


@app.route("/health")
def health():
    return jsonify(status="ok", urllib3=urllib3.__version__)


if __name__ == "__main__":
    cfg = load_config(os.path.join(os.path.dirname(__file__), "config.yml"))
    app.run(host="127.0.0.1", port=cfg.get("port", 5000), debug=cfg.get("debug", False))
