# Steganography Assignment — Discussion & Deployment Guide

## CSE 5381/4381 — Information Security II, Spring 2026

---

## How to Run Locally

```bash
pip install flask
python app.py
# Visit http://localhost:5000
```

## Deployed on Render.com

- https://cse4381-assignment3.onrender.com

login credentials (defined in app.py):

- `aturnbow / password123`

## How the Algorithm Works

### Embedding (hiding M inside P)

1. A 32-bit big-endian integer encoding `len(M)` is prepended to M to form the **payload**.
2. Both P and the payload are converted to bit arrays.
3. Starting at bit index **S** in P, every **L**-th bit is overwritten with the next payload bit.
4. If **C** (mode) specifies a cycling list (e.g. `8, 16, 28`), the period rotates through the list in order, repeating indefinitely.
5. The modified bit array is written back as bytes.

### Extraction (recovering M from stego file)

1. Using the same S and L (and the same cycling position in L if mode C), read 32 bits to recover `len(M)`.
2. Continue reading `len(M) × 8` bits to recover M.
3. The period sequence is **not reset** between reading the header and reading M — it is one continuous pass, matching the embed pass exactly.

### Reversibility

The process is reversible as long as S, L, and the cycling mode C are known. The 32-bit length header makes extraction self-contained — no separate metadata file is needed.

---

## Discussion: How Could an Attacker Find M, Given Only L?

Suppose an attacker intercepts the stego file and knows only L (but not S or M).

### 2 ways they could attack are:

**Brute-force S with known L**

S is typically relatively small (0–a few hundred). An attacker who knows L can try every reasonable S value, extract the 32-bit header for each, and check whether it yields a "reasonable" message length.

OR

**Known-plaintext attack on P**

If the attacker also has access to the original unmodified P (e.g., from a public image database), they can XOR P with the stego file bit-by-bit. The differences will appear at positions `S, S+L, S+2L, …`, immediately revealing L (if not already known) and yielding M directly.

### Mitigations implemented:

- Mode C (cycling L) disrupts simple interval-based detection — the gap between replaced bits is no longer constant.
- Skipping S bits protects file format headers, keeping the file valid and less suspicious.
- The message M could additionally be **encrypted** before embedding (e.g., AES-256) so that even if an attacker extracts the payload bits, they see ciphertext rather than plaintext.

---

## Citations

- Bit manipulation reference: http://graphics.stanford.edu/~seander/bithacks.html
- Bitstring library: https://github.com/scott-griffiths/bitstring
- Steganography overview: https://www.wired.com/story/steganography-hacker-lexicon/
- Steganography tutorial: https://null-byte.wonderhowto.com/how-to/introduction-steganography-its-uses-0155310/
- RS analysis paper: https://www-users.cs.umn.edu/~hoppernj/tc-stego.pdf
- Flask documentation: https://flask.palletsprojects.com/
- Werkzeug security utilities: https://werkzeug.palletsprojects.com/en/latest/utils/
- Also a little help from claude to reword and format this discussion file as well as add clarifying comments on app.py
