# Steganography Assignment — Discussion & Deployment Guide
## CSE 5381/4381 — Information Security II, Spring 2026

---

## How to Run Locally

```bash
pip install flask
python app.py
# Visit http://localhost:5000
```

Demo login credentials (defined in app.py):
- `alice / password123`
- `bob / securepass`

---

## How the Algorithm Works

### Embedding (hiding M inside P)

1. A 32-bit big-endian integer encoding `len(M)` is prepended to M to form the **payload**.
2. Both P and the payload are converted to bit arrays (MSB-first).
3. Starting at bit index **S** in P, every **L**-th bit is overwritten with the next payload bit.
4. If **C** (mode) specifies a cycling list (e.g. `8, 16, 28`), the period rotates through the list in order, repeating indefinitely.
5. The modified bit array is written back as bytes.

### Extraction (recovering M from stego file)

1. Using the same S and L (and the same cycling position in L if mode C), read 32 bits to recover `len(M)`.
2. Continue reading `len(M) × 8` bits to recover M.
3. The period sequence is **not reset** between reading the header and reading M — it is one continuous pass, matching the embed pass exactly.

### Reversibility

The process is perfectly reversible as long as S, L, and the cycling mode C are known. The 32-bit length header makes extraction self-contained — no separate metadata file is needed.

---

## Discussion: How Could an Attacker Find M, Given Only L?

Suppose an attacker intercepts the stego file and knows only L (but not S or M).

### Attack approaches:

**1. Brute-force S with known L**

S is typically small (0–a few hundred). An attacker who knows L can try every plausible S value, extract the 32-bit header for each, and check whether it yields a "reasonable" message length (i.e., `len(M) < len(P) / L`). This narrows it down quickly.

**2. Statistical / correlation analysis**

Every L-th bit in P has been replaced. If the attacker knows or can estimate the statistical distribution of the carrier type (e.g., JPEG DCT coefficients, WAV PCM samples), they can compare the stego file against expected distributions. Bits that were replaced will show a different distribution, revealing which positions were altered and therefore the value of L used.

**3. Chi-squared attack (RS analysis)**

For images, techniques like the RS (Regular–Singular) analysis measure distortions introduced at regular intervals. If L = 8, every byte's LSB is replaced — classic LSB steganography — and this is detectable with ~95% accuracy on modern tools even without knowing L in advance.

**4. Known-plaintext attack on P**

If the attacker also has access to the original unmodified P (e.g., from a public image database), they can XOR P with the stego file bit-by-bit. The differences will appear at positions `S, S+L, S+2L, …`, immediately revealing L (if not already known) and yielding M directly.

### Mitigations implemented:
- Mode C (cycling L) disrupts simple interval-based detection — the gap between replaced bits is no longer constant.
- Skipping S bits protects file format headers, keeping the file valid and less suspicious.
- The message M could additionally be **encrypted** before embedding (e.g., AES-256) so that even if an attacker extracts the payload bits, they see ciphertext rather than plaintext.

---

## Deployment (Making it Publicly Accessible)

### Option A: Microsoft Azure (free via UTA)

```bash
# Install Azure CLI, then:
az login
az webapp up --name stegovault --runtime PYTHON:3.11 --sku F1
```

Set `FLASK_SECRET_KEY` as an environment variable in the Azure portal.

### Option B: AWS Free Tier (EC2 or Elastic Beanstalk)

```bash
pip install awsebcli
eb init -p python-3.11 stegovault
eb create stegovault-env
eb open
```

### Option C: Render.com (simplest, free tier)

1. Push code to GitHub.
2. Create a new Web Service on render.com, point to the repo.
3. Set build command: `pip install flask` and start command: `python app.py`.

### Production notes:
- Replace the in-memory `USERS` and `POSTS` stores with a proper database (SQLite + SQLAlchemy is sufficient for a class project).
- Set `debug=False` and use a strong random `SECRET_KEY`.
- Store uploaded files on S3 or Azure Blob instead of the local filesystem.

---

## Citations

- Bit manipulation reference: http://graphics.stanford.edu/~seander/bithacks.html
- Bitstring library: https://github.com/scott-griffiths/bitstring
- Steganography overview: https://www.wired.com/story/steganography-hacker-lexicon/
- Steganography tutorial: https://null-byte.wonderhowto.com/how-to/introduction-steganography-its-uses-0155310/
- RS analysis paper: https://www-users.cs.umn.edu/~hoppernj/tc-stego.pdf
- Flask documentation: https://flask.palletsprojects.com/
- Werkzeug security utilities: https://werkzeug.palletsprojects.com/en/latest/utils/
