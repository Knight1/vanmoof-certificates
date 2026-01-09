# vanmoof-certificates

A Go tool to fetch and parse VanMoof SA5 and Series 6 bike certificates.  
This tool authenticates with VanMoof's API, retrieves your bikes, generates Ed25519 key pairs, and creates certificates for your SA5 or later bikes.  
Currently this is the SA5 and SA6 bikes. So to list it S5, A5, Series 6, Series 6 Open.    

If the RegEx does not match your Bikes Framenumber, open a PR, Issue or contact me.  
If you have a Series 6 (Open) and you want to invite me as a guest, just contact me :)  
Pull Requests are welcome! ❤️

## Features

- Authenticate with VanMoof API
- Retrieve and filter SA5 or later bikes from your account
- Generate Ed25519 key pairs
- Create and parse bike certificates
- Interactive or command-line bike selection
- Debug mode for troubleshooting

## Usage & Installation
See [USAGE.md](USAGE.md)

**Key Format (as used in crypto.go):**
- **Private key**: 64 bytes in base64 encoding (Ed25519 seed concatenated with public key)
- **Public key**: 32 bytes in base64 encoding (raw Ed25519 public key)
- **Encoding**: Standard base64 (`base64.StdEncoding` in Go)
- **No additional prefixes**: Unlike some implementations, this uses raw keys without metadata

**Important Notes:**
- Some implementations may prefix the public key with 0x00 (33 bytes total) - this is also accepted
- The private key from `ed25519.GenerateKey()` is 64 bytes: 32-byte seed + 32-byte public key

## Example Output

```
Privkey = ✂️
Pubkey = Yd2bYMB3+vs4cCnDtPbcaM164KIl2zs05AK2jt/K6Gs=

Bike ID: 1337
Frame number: ^[A-Z]{6}\d{5}[A-Z]{2}$
Bike is an SA5
Certificate:
-----------
{"certificate":"BASE64_ENCODED_CERTIFICATE"}
-----------

Parsing certificate...
Total Certificate Length: 166 bytes

--- Extracted from Certificate ---
Embedded Public Key (Base64): Yd2bYMB3+vs4cCnDtPbcaM164KIl2zs05AK2jt/K6Gs=
AFM (Authorized Frame Module): ✂️
...
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-email` | VanMoof email address | Prompt if not provided |
| `-password` | VanMoof password | Prompt if not provided |
| `-bikes` | Bikes to process: 'all', IDs (comma-separated), or 'ask' | `all` |
| `-debug` | Enable debug output | `false` |
| `-cert` | Base64 encoded certificate to parse | - |
| `-pubkey` | Base64 encoded public key (optional) | - |
| `-bikeid` | Bike ID for verification (optional) | - |
| `-genkey` | Generate Ed25519 key pair and exit | - |
| `-version` | Print version information | - |

## Requirements

- Go 1.24 or later
- VanMoof account with registered SA5 or later bike(s)

## Certificate Structure

VanMoof bike certificates use a binary format consisting of an Ed25519 signature followed by a CBOR-encoded payload.

### Overall Format

```
[64 bytes: Ed25519 Signature] + [Variable length: CBOR Payload]
```

### Signature (64 bytes)

The first 64 bytes contain an Ed25519 signature that cryptographically signs the CBOR payload:

- **Bytes 0-31**: R component of the Ed25519 signature
- **Bytes 32-63**: S component of the Ed25519 signature

This signature is created by VanMoof's Certificate Authority (CA) and can be verified using the CA's public key to ensure the certificate is authentic and hasn't been tampered with.

### CBOR Payload Structure

Starting at byte 64, the certificate contains a CBOR-encoded map with the following fields:

| Key | Type | Description | Example |
|-----|------|-------------|---------|
| `i` | uint32 | Certificate ID | `1337` |
| `f` | string | Frame Module serial number (AFM - Authorized Frame Module) | `"SVTBKLdddddLL"` |
| `b` | string | Bike Module serial number (ABM - Authorized Bike Module) | `"SVTBKLdddddLL"` |
| `e` | uint32 | Certificate expiry (Unix timestamp) | `1767668550` |
| `r` | uint8 | Role/Access level (0-15) | `7` |
| `u` | bytes[16] | User UUID (without hyphens) | `uuid3` |
| `p` | bytes[32] | User's Ed25519 public key | 32-byte public key |

### Access Levels (Role Field)

The `r` (role) field determines what permissions the certificate grants:

| Value | Access Level | Description |
|-------|--------------|-------------|
| `0x00` | Guest | Read-only access |
| `0x01` | Limited Access | Restricted permissions |
| `0x03` | Owner | Standard owner access |
| `0x07` | Owner | Full control (unlock, settings, firmware) |
| `0x0F` | Service/Admin | Extended permissions for service/maintenance |

### Certificate Binding

The certificate cryptographically binds together:

1. **Specific Bike**: Via frame/bike module serials (`f`, `b`)
2. **Certificate ID**: The `i` field varies per certificate
3. **Specific User**: Via user UUID (`u`)
4. **Specific Public Key**: Via user's Ed25519 public key (`p`)
5. **Access Level**: Via role field (`r`)
6. **Validity Period**: Via expiry timestamp (`e`)

When a bike validates a certificate, it verifies:
- The Ed25519 signature is valid (signed by VanMoof CA)
- The frame/bike module serials match this bike
- The certificate hasn't expired
- The user's public key matches the one in the certificate

### Example Certificate Breakdown

Decoded structure:
- **Signature**: `...` (64 bytes)
- **Certificate ID**: `1337`
- **Frame Module Serial (AFM)**: `SVTBKLdddddLL`
- **Bike Module Serial (ABM)**: `SVTBKLdddddLL`
- **Expiry**: `1767668550` (January 6, 2026 04:02:38 CET)
- **Role**: `7` (Owner - Full Control)
- **User UUID**: `1111111-1111-3111-1111-111111111111` (UUIDv3)
- **Public Key**: `KIQtqMxZ9Vdj3YLfNgNHjUB4WN4gLtDX/FwpiyFiUMs=`

### CBOR Encoding Details

The payload uses CBOR (Concise Binary Object Representation, RFC 8949) encoding:

```
0xa7                    # Map with 7 entries
  0x61 0x69             # Text string "i"
  0x1a 0x00 0x02 0xa7 0x66  # uint32: 1337 (Certificate ID)
  
  0x61 0x66             # Text string "f" 
  0x6d                  # Text string, 13 bytes
  "SVTBKLdddddLL"       # Frame Module serial (AFM)
  
  0x61 0x62             # Text string "b"
  0x6d                  # Text string, 13 bytes  
  "SVTBKLdddddLL"       # Bike Module serial (ABM)
  
  0x61 0x65             # Text string "e"
  0x1a 0x69 0x5c 0x7b 0x46  # uint32: 1767668550
  
  0x61 0x72             # Text string "r"
  0x07                  # uint: 7
  
  0x61 0x75             # Text string "u"
  0x50                  # Byte string, 16 bytes
  [16 bytes: user UUIDv3]
  
  0x61 0x70             # Text string "p"
  0x58 0x20             # Byte string, 32 bytes
  [32 bytes: public key]
```

### Security Notes

- The signature ensures the certificate cannot be modified without detection
- Each certificate is bound to a specific user UUID from the VanMoof account
- Certificates have an expiry date (typically set ~1 week in the future)
- The CA public key needed for signature verification is likely embedded in the bike firmware
- It seems that there is no revocation nor public logging. If someone has access to the VanMoof account with your bike, they can generate certificates without you noticing. Furthermore, these certificates are irrevocable. So the only way to secure the bike would be to lock it in the garage or basement until 7 days have passed.
- It is currently not known how the bike knows the time after a power loss. This would be either via GSM, GPS, or the phone. What happens if a jammer is in place or if the GPS time was spoofed is currently unknown. In the case where you can spoof an older time, you could in theory unlock the bike with an older certificate if the bike accepts the new time as the "correct time".
- If you are 7 days without internet, you can no longer unlock your bike with your phone. Only via the backup code. 
- What happens after 10 years? Since VanMoof reverted the 10-year certificate lifetime, it is currently not possible to control the bike (besides the backup code) without talking to the VanMoof API with the key to issue certificates. Alternatively, logic could be implemented where 2FA is required to issue a certificate valid for more than 7 days.
