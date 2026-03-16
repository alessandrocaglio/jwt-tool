# jwt-tool 🛠️

A security-first JWT CLI for developers and platform engineers for inspecting and verifying JSON Web Tokens (JWT). Built with Go for speed, reliability, and ease of use in both manual workflows and automated pipelines.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Fast](https://img.shields.io/badge/Performance-%3C50ms-green)](https://github.com/alessandrocaglio/jwt-tool)

## 🚀 Key Features

- **Flexible Input (The Resolver Pattern):** Read tokens or keys from direct strings, local files (`@path`), or `stdin` (`-`).
- **Unified Inspection & Verification:** Always decodes and displays token content, with automatic cryptographic validation if a key is provided.
- **Signature Verification:** Supports HMAC (HS256/384/512), RSA (RS256/384/512), ECDSA (ES256/384/512), and EdDSA (Ed25519).
- **JWKS Integration:** Fetch and validate against local or remote JSON Web Key Sets (JWKS).
- **Keycloak Integration:** Easily fetch OIDC discovery information or introspect tokens from Keycloak realms.
- **Smart Output:** Default machine-readable **JSON** output, with a beautiful colorized **Table** view for humans.
- **Timestamp Awareness:** Automatically converts `exp`, `iat`, `nbf`, `auth_time`, and `updated_at` claims into human-readable date-time strings.
- **Security Hardened:** Explicitly rejects `none` algorithms and protects against key confusion attacks.

---

## 📥 Installation

```bash
# Clone the repository
git clone https://github.com/alessandrocaglio/jwt-tool.git
cd jwt-tool

# Build the binary
go build -o jwt-tool ./cmd/jwt-tool/main.go

# (Optional) Move to your PATH
sudo mv jwt-tool /usr/local/bin/
```

---

## 🛠 Usage Guide

### 1. Inspecting & Decoding
Parse the header and payload without performing cryptographic verification.
`jwt-tool` defaults to this action if no subcommand is provided.

```bash
# Default action (direct string)
jwt-tool <TOKEN>

# Default action (stdin)
echo <TOKEN> | jwt-tool

# Explicit subcommand
jwt-tool inspect <TOKEN>

# From a file
jwt-tool inspect @path/to/token.jwt

# Human-readable table output
jwt-tool <TOKEN> -o table
```

### 2. Verifying
Cryptographically validate the signature and time-based claims by providing a verification key. 

**Note:** The tool will always display the decoded token content first, even if verification fails. If verification fails, the tool will exit with **Code 2**.

```bash
# Using a symmetric secret
jwt-tool inspect <TOKEN> --secret "my-super-secret"

# Using a Public Key (RSA/ECDSA/EdDSA)
jwt-tool inspect <TOKEN> --pem @public_key.pem

# Using a remote JWKS endpoint
jwt-tool inspect <TOKEN> --jwks https://auth.example.com/.well-known/jwks.json

# Verification also works with the default command
jwt-tool <TOKEN> --secret "my-super-secret"
```

### 3. Key Generation
Generate asymmetric key pairs for JWT signing.

```bash
# Generate RSA-2048 (prints to stdout)
jwt-tool keygen

# Generate ECDSA P-384 and save to files
jwt-tool keygen -a ecdsa -c P384 -f mykey
# Results in 'mykey' (private) and 'mykey.pub' (public)

# Generate EdDSA (Ed25519) and save to files
jwt-tool keygen -a eddsa -f mykey-ed
```

### 4. Keycloak Integration
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

#### Token Login
```bash
# Get an access token using client credentials (prints token string only by default)
jwt-tool keycloak login --url https://keycloak.example.com --realm myrealm --client-id my-client --client-secret my-secret

# Get an access token using password grant
jwt-tool keycloak login --url https://keycloak.example.com --realm myrealm --client-id my-client --client-secret my-secret --username jdoe --password pass

# Display full response details in a table
jwt-tool keycloak login ... -o table
```

#### Token Introspection
```bash
# Introspect a token (requires client credentials)
jwt-tool keycloak introspect <TOKEN> --url https://keycloak.example.com --realm myrealm --client-id my-client --client-secret my-secret

# From a file
jwt-tool keycloak introspect @token.jwt --url ...

# Human-readable status and details
jwt-tool keycloak introspect <TOKEN> ... -o table
```

### 5. Version
Print the version, commit hash, and build date.

```bash
jwt-tool version
```

---

## 📊 Output Formats

Toggle between formats using the `-o` or `--output` flag.

| Format | Command | Description |
| :--- | :--- | :--- |
| **JSON** | `-o json` | **(Default)** Indented JSON, perfect for `jq` or scripting. |
| **Table** | `-o table` | Colorized, human-friendly table with date-time conversions. |
| **OpenID** | `-o openid` | Raw `openid-configuration` JSON from the server (for `keycloak info`). |

### JSON Schema Extensions
When verification is requested, `jwt-tool` adds an `x-validation` field to the JSON output. This follows the industry convention of using an `x-` prefix for tool-specific metadata, ensuring that the original JWT structure (header, payload, signature) remains untampered and clearly separated from the tool's assessment.

**Example (Failed Verification):**
```json
{
  "header": { ... },
  "payload": { ... },
  "signature": "...",
  "x-validation": {
    "valid": false,
    "status": "INVALID",
    "error": "token is expired by 1h5m20s",
    "algorithm": "RS256"
  }
}
```

---

## 📑 CLI Reference

### Global Flags
- `-o, --output <string>`: Output format. Options: `json` (default), `table`, `openid`.

### `inspect` Flags
- *Usage: `jwt-tool inspect [token|-|@file] [flags]`*
- `--secret <string>`: Symmetric secret for HMAC.
- `--pem <path>`: Path to RSA/ECDSA/EdDSA public key file (`@path`).
- `--jwks <uri|path>`: Path or URL to a JWKS.
- `--leeway <duration>`: Clock skew tolerance (e.g., `1m`, `30s`).
- *Aliases: `decode`, `verify`*

### `keygen` Flags
- `-a, --alg <string>`: Algorithm: `rsa` (default), `ecdsa`, or `eddsa`.
- `-b, --bits <int>`: RSA bit size: `2048`, `3072`, `4096`.
- `-c, --curve <string>`: ECDSA curve: `P256`, `P384`, `P521`.
- `-f, --file <path>`: Save to file (creates `.pub` for public key). **If omitted, prints both private and public keys to stdout.**

### `keycloak info` Flags
- `--url <string>`: Keycloak base URL.
- `--realm <string>`: Keycloak realm name.

### `keycloak introspect` Flags
- *Usage: `jwt-tool keycloak introspect [token|-|@file] [flags]`*
- `--url <string>`: Keycloak base URL.
- `--realm <string>`: Keycloak realm name.
- `--client-id <string>`: Keycloak Client ID.
- `--client-secret <string>`: Keycloak Client Secret.

### `keycloak login` Flags
- `--url <string>`: Keycloak base URL.
- `--realm <string>`: Keycloak realm name.
- `--client-id <string>`: Keycloak Client ID.
- `--client-secret <string>`: Keycloak Client Secret.
- `--username <string>`: Username (for password grant).
- `--password <string>`: Password (for password grant).
- `--scope <string>`: Token scope (default: `openid`).

### `version`
- *Usage: `jwt-tool version`*
- Prints version, commit hash, and build date.

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
