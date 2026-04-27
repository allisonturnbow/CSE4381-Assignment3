"""
Steganography Web Service
CSE 4381 - Information Security II
References:
  - http://graphics.stanford.edu/~seander/bithacks.html
  - https://github.com/scott-griffiths/bitstring
"""

import os
import io
import math
from PIL import Image
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file,
    flash,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "stego_secret_key_change_in_production"
app.config["MAX_CONTENT_LENGTH"] = None  # no upload size limit

UPLOAD_FOLDER = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "static", "uploads"
)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── Simple in-memory user store ──────────
USERS = {"aturnbow": generate_password_hash("password123")}

# ── In-memory post store ───────────────────────────────────────────────────
POSTS = (
    []
)  # list of dicts: {id, filename, original_name, is_image, uploader, caption, params}


#  STEGANOGRAPHY algorithm


def bytes_to_bits(data: bytes) -> list[int]:
    """Convert bytes → list of individual bits (MSB first)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    """Convert list of bits → bytes (MSB first, zero-pads last byte)."""
    # Pad to multiple of 8
    while len(bits) % 8 != 0:
        bits.append(0)
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def get_period_sequence(L: int | list[int], count: int) -> list[int]:
    """
    Build a repeating sequence of period values of length `count`.
    Mode C: if L is a list, cycle through it; if int, constant.
    """
    if isinstance(L, int):
        return [L] * count
    seq = []
    for i in range(count):
        seq.append(L[i % len(L)])
    return seq


def embed(
    carrier: bytes, message: bytes, S: int, L_raw, prepend_length: bool = True
) -> bytes:
    """
    Hide `message` inside `carrier`.

    Parameters
    ----------
    carrier       : raw bytes of the carrier file (P)
    message       : raw bytes of the secret message (M)
    S             : number of bits to skip at the start of carrier
    L_raw         : periodicity – int OR list[int] for mode C cycling
    prepend_length: if True, embed a 32-bit big-endian message-length header
                    so extraction knows how many bits to pull out

    Returns modified carrier bytes.
    """
    carrier_bits = bytes_to_bits(carrier)

    # Optionally prepend 4-byte (32-bit) message length so we can extract exactly
    if prepend_length:
        length_bytes = len(message).to_bytes(4, "big")
        payload_bits = bytes_to_bits(length_bytes + message)
    else:
        payload_bits = bytes_to_bits(message)

    num_payload_bits = len(payload_bits)

    # Build the list of carrier bit-indices we will overwrite
    # Starting at index S, pick every L-th bit (cycling if mode C)
    def _next_p(pos):
        if isinstance(L_raw, int):
            return L_raw, pos
        return L_raw[pos % len(L_raw)], pos + 1

    idx = S
    period_pos = 0
    for payload_bit in payload_bits:
        if idx >= len(carrier_bits):
            raise ValueError(
                f"Carrier too small: need at least {idx} bits, have {len(carrier_bits)}"
            )
        carrier_bits[idx] = payload_bit
        p, period_pos = _next_p(period_pos)
        idx += p

    return bits_to_bytes(carrier_bits)


def extract(stego: bytes, S: int, L_raw) -> bytes:
    """
    Extract the hidden message from a stego file.

    Reads the 32-bit length header first, then pulls exactly that many
    message bits from the subsequent carrier positions.
    Uses a single unified period sequence so cycling L stays in sync.
    """
    stego_bits = bytes_to_bits(stego)

    # --- Phase 1: read 32-bit length header using first 32 period values -----
    header_bit_count = 32
    header_bits = []
    idx = S
    period_iter_pos = 0  # tracks position in cycling L sequence

    # iterator-style approach so we can resume after reading header
    def next_period(pos):
        if isinstance(L_raw, int):
            return L_raw, pos
        val = L_raw[pos % len(L_raw)]
        return val, pos + 1

    for _ in range(header_bit_count):
        header_bits.append(stego_bits[idx])
        p, period_iter_pos = next_period(period_iter_pos)
        idx += p

    msg_len = int("".join(str(b) for b in header_bits), 2)

    # --- Phase 2: read message bits, continuing the same period sequence -----
    msg_bits = []
    for _ in range(msg_len * 8):
        msg_bits.append(stego_bits[idx])
        p, period_iter_pos = next_period(period_iter_pos)
        idx += p

    return bits_to_bytes(msg_bits)[:msg_len]


IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}


def embed_image_stego(carrier_bytes: bytes, message: bytes, S: int, L_raw) -> bytes:
    """Embed message in image pixel data so the output remains a valid PNG."""
    img = Image.open(io.BytesIO(carrier_bytes)).convert("RGB")
    pixel_bytes = bytes(img.tobytes())
    stego_pixel_bytes = embed(pixel_bytes, message, S, L_raw)
    stego_img = Image.frombytes("RGB", img.size, stego_pixel_bytes)
    out = io.BytesIO()
    stego_img.save(out, format="PNG")
    return out.getvalue()


def extract_image_stego(stego_bytes: bytes, S: int, L_raw) -> bytes:
    """Extract message from image pixel data."""
    img = Image.open(io.BytesIO(stego_bytes)).convert("RGB")
    pixel_bytes = bytes(img.tobytes())
    return extract(pixel_bytes, S, L_raw)


def parse_L(raw: str):
    """
    Parse user-supplied L value.
    Accepts a single integer ("8") or a comma-separated list ("8,16,28").
    Returns int or list[int].
    """
    parts = [p.strip() for p in raw.split(",")]
    if len(parts) == 1:
        return int(parts[0])
    return [int(p) for p in parts]


#  AUTH ROUTES


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed = USERS.get(username)
        if hashed and check_password_hash(hashed, password):
            session["user"] = username
            flash("Logged in successfully!", "success")
            return redirect(url_for("index"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out.", "info")
    return redirect(url_for("index"))


#  MAIN / PUBLIC ROUTES


@app.route("/")
def index():
    return render_template("index.html", posts=POSTS, user=session.get("user"))


#  AUTHENTICATED: EMBED


@app.route("/embed", methods=["GET", "POST"])
def embed_route():
    if "user" not in session:
        flash("Please log in to embed messages.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        carrier_file = request.files["carrier"]
        message_file = request.files.get("message_file")
        message_text = request.form.get("message_text", "").strip()
        S = int(request.form.get("S", 0))
        L_raw = request.form.get("L", "8")
        caption = request.form.get("caption", "")

        try:
            L = parse_L(L_raw)
        except ValueError:
            flash("L must be an integer or comma-separated list of integers.", "error")
            return redirect(url_for("embed_route"))

        carrier_bytes = carrier_file.read()
        orig_name = secure_filename(carrier_file.filename)
        ext = os.path.splitext(orig_name)[1].lower()
        is_image = ext in IMAGE_EXTS

        # Message: prefer uploaded file, fall back to text
        if message_file and message_file.filename:
            msg_bytes = message_file.read()
        elif message_text:
            msg_bytes = message_text.encode("utf-8")
        else:
            flash("Please provide a message (file or text).", "error")
            return redirect(url_for("embed_route"))

        try:
            if is_image:
                # Work on pixel data so the output remains a valid image
                stego_bytes = embed_image_stego(carrier_bytes, msg_bytes, S, L)
                orig_name = os.path.splitext(orig_name)[0] + ".png"
            else:
                stego_bytes = embed(carrier_bytes, msg_bytes, S, L)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("embed_route"))

        # Save stego file
        stego_filename = f"stego_{len(POSTS)}_{orig_name}"
        stego_path = os.path.join(UPLOAD_FOLDER, stego_filename)
        with open(stego_path, "wb") as f:
            f.write(stego_bytes)

        L_display = L_raw  # keep original string for display

        POSTS.append(
            {
                "id": len(POSTS),
                "filename": stego_filename,
                "original_name": orig_name,
                "is_image": is_image,
                "uploader": session["user"],
                "caption": caption,
                "params": {"S": S, "L": L_display},
            }
        )

        flash(f"File posted successfully with hidden message!", "success")
        return redirect(url_for("index"))

    return render_template("embed.html", user=session.get("user"))


#  AUTHENTICATED: EXTRACT


@app.route("/extract", methods=["GET", "POST"])
def extract_route():
    if "user" not in session:
        flash("Please log in to extract messages.", "error")
        return redirect(url_for("login"))

    extracted = None
    if request.method == "POST":
        stego_file = request.files["stego"]
        S = int(request.form.get("S", 0))
        L_raw = request.form.get("L", "8")

        try:
            L = parse_L(L_raw)
        except ValueError:
            flash("L must be an integer or comma-separated list of integers.", "error")
            return redirect(url_for("extract_route"))

        stego_bytes = stego_file.read()
        stego_ext = os.path.splitext(secure_filename(stego_file.filename))[1].lower()

        try:
            if stego_ext in IMAGE_EXTS:
                msg_bytes = extract_image_stego(stego_bytes, S, L)
            else:
                msg_bytes = extract(stego_bytes, S, L)
            # Try to decode as text; fall back to hex dump
            try:
                extracted = msg_bytes.decode("utf-8")
            except UnicodeDecodeError:
                extracted = msg_bytes.hex()
        except Exception as e:
            flash(f"Extraction failed: {e}", "error")

    return render_template(
        "extract.html", user=session.get("user"), extracted=extracted
    )


#  DOWNLOAD stego file (public)


@app.route("/download/<int:post_id>")
def download(post_id):
    post = next((p for p in POSTS if p["id"] == post_id), None)
    if not post:
        flash("Post not found.", "error")
        return redirect(url_for("index"))
    path = os.path.join(UPLOAD_FOLDER, post["filename"])
    return send_file(path, as_attachment=True, download_name=post["original_name"])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
