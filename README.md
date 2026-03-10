# jwt-tool 🛠️

A security-first JWT CLI for developers and platform engineers for inspecting and verifying JSON Web Tokens (JWT). Built with Go for speed, reliability, and ease of use in both manual workflows and automated pipelines.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Fast](https://img.shields.io/badge/Performance-%3C50ms-green)](https://github.com/alessandrocaglio/jwt-tool)

## 🚀 Key Features

- **Flexible Input (The Resolver Pattern):** Read tokens or keys from direct strings, local files (`@path`), or `stdin` (`-`).
- **Signature Verification:** Supports HMAC (HS256/384/512), RSA (RS256/384/512), and ECDSA (ES256/384/512).
- **JWKS Integration:** Fetch and validate against local or remote JSON Web Key Sets (JWKS).
- **Keycloak Integration:** Easily fetch OIDC discovery information from Keycloak realms.
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
`jwt-tool` defaults to this action if no subcommand is provided.

```bash
# Default action (direct string)
jwt-tool <TOKEN>

# Default action (stdin)
echo <TOKEN> | jwt-tool

# Explicit subcommand
jwt-tool decode <TOKEN>

# From a file
jwt-tool decode @path/to/token.jwt

# Human-readable table output
jwt-tool <TOKEN> -o table
```

### 2. Verification
Cryptographically validate the signature and time-based claims.

```bash
# Using a symmetric secret
jwt-tool verify <TOKEN> --secret "my-super-secret"

# Using a Public Key (RSA/ECDSA)
jwt-tool verify <TOKEN> --pem @public_key.pem

# Using a remote JWKS endpoint
jwt-tool verify <TOKEN> --jwks https://auth.example.com/.well-known/jwks.json
```

### 3. Key Generation
Generate asymmetric key pairs for JWT signing.

```bash
# Generate RSA-2048 (prints to stdout)
jwt-tool keygen

# Generate ECDSA P-384 and save to files
jwt-tool keygen -a ecdsa -c P384 -f mykey
# Results in 'mykey' (private) and 'mykey.pub' (public)
```

### 3. Keycloak Integration
Fetch OIDC discovery information or introspect a token from a Keycloak realm.

#### Discovery Info
```bash
# Fetch and display discovery info as JSON (default)
jwt-tool keycloak info --url https://keycloak.example.com --realm myrealm

# Display as a human-readable table
jwt-tool keycloak info --url https://keycloak.example.com --realm myrealm -o table

# Output the raw openid-configuration from the endpoint
jwt-tool keycloak info --url https://keycloak.example.com --realm myrealm -o openid
```

#### Token Introspection
```bash
# Introspect a token (requires client credentials)
jwt-tool keycloak introspect <TOKEN> \
  --url https://keycloak.example.com \
  --realm myrealm \
  --client-id my-client \
  --client-secret my-secret

# Human-readable table output
jwt-tool keycloak introspect <TOKEN> ... -o table
```

---

---

## 📊 Output Formats

Toggle between formats using the `-o` or `--output` flag.

| Format | Command | Description |
| :--- | :--- | :--- |
| **JSON** | `-o json` | **(Default)** Indented JSON, perfect for `jq` or scripting. |
| **Table** | `-o table` | Colorized, human-friendly table with date-time conversions. |
| **OpenID** | `-o openid` | Raw `openid-configuration` JSON from the server (for `keycloak info`). |

---

## 📑 CLI Reference

### Global Flags
- `-o, --output <string>`: Output format. Options: `json` (default), `table`, `openid`.

### `decode` Flags
- *None (inherits global flags)*

### `verify` Flags
- `--secret <string>`: Symmetric secret for HMAC.
- `--pem <path>`: Path to RSA/ECDSA public key file (`@path`).
- `--jwks <uri|path>`: Path or URL to a JWKS.
- `--leeway <duration>`: Clock skew tolerance (e.g., `1m`, `30s`).

### `keycloak info` Flags
- `--url <string>`: Keycloak base URL.
- `--realm <string>`: Keycloak realm name.

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
