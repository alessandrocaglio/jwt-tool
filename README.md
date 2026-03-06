# jwt-tool 🛠️

A high-performance, security-first CLI utility for inspecting and verifying JSON Web Tokens (JWT). Built with Go for speed, reliability, and ease of use in both manual workflows and automated pipelines.

[![Go Version](https://img.shields.io/github/go-mod/go-version/redhat-labs/jwt-tool?color=00ADD8&label=Go&logo=go)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Fast](https://img.shields.io/badge/Performance-%3C50ms-green)](https://github.com/redhat-labs/jwt-tool)

## 🚀 Key Features

- **Flexible Input (The Resolver Pattern):** Read tokens or keys from direct strings, local files (`@path`), or `stdin` (`-`).
- **Signature Verification:** Supports HMAC (HS256/384/512), RSA (RS256/384/512), and ECDSA (ES256/384/512).
- **JWKS Integration:** Fetch and validate against local or remote JSON Web Key Sets (JWKS).
- **Smart Output:** Default machine-readable **JSON** output, with a beautiful colorized **Table** view for humans.
- **Timestamp Awareness:** Automatically converts `exp`, `iat`, and `nbf` claims into human-readable date-time strings.
- **Security Hardened:** Explicitly rejects `none` algorithms and protects against key confusion attacks.

---

## 📥 Installation

```bash
# Clone the repository
git clone https://github.com/redhat-labs/jwt-tool.git
cd jwt-tool

# Build the binary
go build -o jwt-tool ./cmd/jwt-tool/main.go

# (Optional) Move to your PATH
sudo mv jwt-tool /usr/local/bin/
```

---

## 🛠 Usage Guide

### 1. Decoding (Inspection only)
Parse the header and payload without performing cryptographic verification.

```bash
# Default (reads from stdin)
echo <TOKEN> | jwt-tool decode

# Direct string
jwt-tool decode <TOKEN>

# From a file
jwt-tool decode @path/to/token.jwt

# From stdin (explicit)
cat token.txt | jwt-tool decode -

# Human-readable table output
jwt-tool decode <TOKEN> -o table
```

### 2. Verification
Cryptographically validate the signature and time-based claims.

```bash
# Default (reads from stdin)
echo <TOKEN> | jwt-tool verify --secret "secret"

# Using a symmetric secret
jwt-tool verify <TOKEN> --secret "my-super-secret"
```

# Using a Public Key (RSA/ECDSA)
jwt-tool verify <TOKEN> --pem @public_key.pem

# Using a remote JWKS endpoint
jwt-tool verify <TOKEN> --jwks https://auth.example.com/.well-known/jwks.json

# Adding leeway for clock skew (e.g., 60 seconds)
jwt-tool verify <TOKEN> --secret "secret" --leeway 60s
```

---

## 📊 Output Formats

Toggle between formats using the `-o` or `--output` flag.

| Format | Command | Description |
| :--- | :--- | :--- |
| **JSON** | `-o json` | **(Default)** Indented JSON, perfect for `jq` or scripting. |
| **Table** | `-o table` | Colorized, human-friendly table with date-time conversions. |

---

## 📑 CLI Reference

### Global Flags
- `-o, --output <string>`: Output format. Options: `json` (default), `table`.

### `decode` Flags
- *None (inherits global flags)*

### `verify` Flags
- `--secret <string>`: Symmetric secret for HMAC.
- `--pem <path>`: Path to RSA/ECDSA public key file (`@path`).
- `--jwks <uri|path>`: Path or URL to a JWKS.
- `--leeway <duration>`: Clock skew tolerance (e.g., `1m`, `30s`).

---

## 🚦 Exit Codes

`jwt-tool` uses standard exit codes for automation reliability:

| Code | Meaning |
| :--- | :--- |
| `0` | **Success**: Token is valid and verified. |
| `1` | **System Error**: File not found, network timeout, or malformed input. |
| `2` | **Validation Error**: Expired token, invalid signature, or algorithm mismatch. |

---

## 🧪 Development & Testing

We maintain a 100% logic coverage goal for core components.

```bash
# Run all unit tests
go test ./...

# Run tests with coverage
go test -cover ./...
```

---
