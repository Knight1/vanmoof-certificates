# vanmoof-certificates

A Go tool to fetch and parse VanMoof SA5 and SA6 bike certificates. This tool authenticates with VanMoof's API, retrieves your bikes, generates Ed25519 key pairs, and creates certificates for your SA5 or later bikes. Currently this is the SA5 and SA6 bikes. So to list it S5, A5, S6, A6. SA6 is currently not implemented since I do not have one to test and I don't know the bleProfile Name.  

If the RegEx does not match your Bikes Framenumber, open a PR, Issue or contact me.  
If you have an SA6 and you want to invite me as a guest, just contact me :)  
PRs welcome!

## Features

- Authenticate with VanMoof API
- Retrieve and filter SA5 or later bikes from your account
- Generate Ed25519 key pairs
- Create and parse bike certificates
- Interactive or command-line bike selection
- Debug mode for troubleshooting

## Installation

```console
go build
```

## Usage

### Interactive Mode

Run without any flags to be prompted for credentials:

```console
./vanmoof-certificates
```

This will:
1. Prompt for your VanMoof email
2. Prompt for your password (hidden input)
3. Fetch all SA5 or later bikes and generate certificates

### Command-Line Mode

Provide credentials via flags:

```console
./vanmoof-certificates -email user@example.com -password yourpassword
```

### Select Specific Bikes

**Process all bikes (default):**
```console
./vanmoof-certificates -email user@example.com -password yourpassword -bikes all
```

**Process specific bikes by ID:**
```console
./vanmoof-certificates -email user@example.com -password yourpassword -bikes 176393,138884
```

**Interactive bike selection:**
```console
./vanmoof-certificates -email user@example.com -password yourpassword -bikes ask
```

This will display your SA5 bikes and prompt you to select which ones to process.

### Debug Mode

Enable debug output to see detailed API requests and responses:

```console
./vanmoof-certificates -email user@example.com -debug
```

### Parse Existing Certificate

Parse a certificate without fetching from API:

```console
./vanmoof-certificates -cert "BASE64_CERTIFICATE_STRING"
```

With optional public key verification:

```console
./vanmoof-certificates -cert "BASE64_CERT" -pubkey "BASE64_PUBKEY" -bikeid "BIKE_ID"
```

## Example Output

```
Privkey = ✂️
Pubkey = Yd2bYMB3+vs4cCnDtPbcaM164KIl2zs05AK2jt/K6Gs=

Bike ID: 1337
Frame number: ^[A-Z]{3}[A-Z]{3}\d{5}[A-Z]{2}$
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
| `-debug` | Enable debug output | \`false\` |
| `-cert` | Base64 encoded certificate to parse | - |
| `-pubkey` | Base64 encoded public key (optional) | - |
| `-bikeid` | Bike ID for verification (optional) | - |
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
| `i` | uint32 | Bike API ID from VanMoof's system | `1337` |
| `f` | string | Frame Module serial number | `"SVTBKLdddddXX"` |
| `b` | string | Bike Module serial number | `"SVTBKLdddddXX"` |
| `e` | uint32 | Certificate expiry (Unix timestamp) | `1767668558` |
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

1. **Specific Bike**: Via API ID (`i`) and frame/bike serials (`f`, `b`)
2. **Specific User**: Via user UUID (`u`)
3. **Specific Public Key**: Via user's Ed25519 public key (`p`)
4. **Access Level**: Via role field (`r`)
5. **Validity Period**: Via expiry timestamp (`e`)

When a bike validates a certificate, it verifies:
- The Ed25519 signature is valid (signed by VanMoof CA)
- The bike ID matches this bike
- The certificate hasn't expired
- The user's public key matches the one in the certificate

### Example Certificate Breakdown

Decoded structure:
- **Signature**: `...` (64 bytes)
- **Bike API ID**: `1337`
- **Frame/Bike Serial**: `SVTBKLddddddLL`
- **Expiry**: `1767668550` (January 6, 2026 04:02:38 CET)
- **Role**: `7` (Owner - Full Control)
- **User UUID**: `11111111-1111-3111-1111-111111111111`
- **Public Key**: `KIQtqMxZ9Vdj3yLfNGNHlUB0WN9gLTdX/fwpiTfiUMs=`

### CBOR Encoding Details

The payload uses CBOR (Concise Binary Object Representation, RFC 8949) encoding:

```
0xa7                    # Map with 7 entries
  0x61 0x69             # Text string "i"
  0x1a 0x00 0x02 0xa7 0x56  # uint32: 173910
  
  0x61 0x66             # Text string "f" 
  0x6d                  # Text string, 13 bytes
  "SVTBKL00063OA"       # Frame serial
  
  0x61 0x62             # Text string "b"
  0x6d                  # Text string, 13 bytes  
  "SVTBKL00063OA"       # Bike serial
  
  0x61 0x65             # Text string "e"
  0x1a 0x69 0x5c 0x7b 0x4e  # uint32: 1767668558
  
  0x61 0x72             # Text string "r"
  0x07                  # uint: 7
  
  0x61 0x75             # Text string "u"
  0x50                  # Byte string, 16 bytes
  [16 bytes: user UUID]
  
  0x61 0x70             # Text string "p"
  0x58 0x20             # Byte string, 32 bytes
  [32 bytes: public key]
```

### Security Notes

- The signature ensures the certificate cannot be modified without detection
- Each certificate is bound to a specific user UUID from the VanMoof account
- Certificates have an expiry date (typically set ~1 week in the future)
- The CA public key needed for signature verification is likely embedded in the bike firmware
- It seems that there is no revocation nor public logging. If someone has access to the VanMoof Account with your bike he can generate Certificates without you noticing and even if, they are irrevocable. So the only way to secure the bike would be to lock it in the Garage or Basement until 7 days are passed.
- It is currently not known how the bike knows the time after a power loss. This would be either via GSM, GPS or the Phone. What happens if a jammer is in place or if the GPS Time was spoofed is currently unknown. In the Case where you can spoof an older time you could in theory unlock the bike with an older Certificate if the bike accepts the new time as the "correct time".
- If you are 7 days without Internet, you can no longer unlock your bike with your Phone. Only via the Backup Code. 
- What happens after 10 Years? Since VanMoof reverted the 10 Year Certificate Lifetime it is currently not possible to control the bike (besides the backup Code) without talking to the  VanMoof API with the key to issue Certificates.
