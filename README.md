# vanmoof-certificates

A Go tool to fetch and parse VanMoof SA5 and Series 6 bike certificates.  
This tool authenticates with VanMoof's API, retrieves your bikes, generates Ed25519 key pairs, and creates certificates for your SA5 or later bikes.  
Currently this is the SA5 and SA6 bikes. So to list it S5, A5, Series 6, Series 6 Open.    

If the RegEx does not match your Bikes Framenumber, open a PR, Issue or contact me.  
When you share output, run with `-debug -redact`: it hides your tokens, keys and personal data.  
If you have a Series 6 (Open) and you want to invite me as a guest, just contact me :)  
Pull Requests are welcome! ❤️

## Features

- Authenticate with VanMoof API with token cache (auth token, app token, refresh token) or username/password, logging in again automatically if the server rejects cached tokens
- Saves your key pair, the certificates, BLE keys, bike messages and `getCustomerData` response in its cache (encrypted with `VANMOOF_CACHE_KEY`, or unencrypted only if you accept that with `-cleartext-keys`), and requests every certificate for the saved key pair, so a BLE app needs the private key only once (`-new-key` makes a new one, `-show-saved` shows what's saved)
- Retrieve and filter SA5 and S6 bikes from your account
- List, accept and decline bike sharing invitations (`-invitations`)
- Support for shared/guest bikes via VanMoof's Vehicle Registry API (debug mode shows how long each is shared)
- Generate Ed25519 key pairs
- Create and parse bike certificates
- Generate a self-signed certificate with a key of your own from a JSON config (`-generate`): advanced, for a bike whose module firmware you've changed to trust your key, since a stock bike trusts only VanMoof's
- Show the BLE encryption key of S2/S3/S4 and older bikes (`-show-keys`), including a check for a pending key delivery over BLE (`getBikeMessages`) when no key is available yet
- Interactive or command-line bike selection (by ID or frame number, of any generation)
- Exit status for scripts: `1` if logging in or a certificate failed (including an invalid one), `2` for invalid flags
- Checks the TLS certificates of VanMoof's servers for revocation before sending them anything: with OCSP, the CRL, and Mozilla's OneCRL (the keys and certificates Firefox distrusts, fetched once a run, its content signature checked against Mozilla's root as Firefox checks it), keeping the connections alive. A revoked certificate is refused, and so is one left unconfirmed — including when OneCRL can't be fetched or its signature doesn't check out — unless `-allow-unknown-revocation`. OneCRL catches a compromised CA, which can forge its own OCSP and CRL but can't take itself off Firefox's list
- Keeps secrets (keys, tokens, the password) off disk on Linux, best-effort: locks the process's memory into RAM (`mlockall`, so nothing is swapped) and disables core dumps; it warns and carries on if the `memlock` limit is too low (`ulimit -l`)
- Debug mode for troubleshooting, with `-redact` to share its output without secrets or personal data
- Go package for your own programs: log in, list the bikes, and request and check certificates, with the results as values

## Usage & Installation
See [USAGE.md](USAGE.md), which also covers [using it from scripts and other programs](USAGE.md#using-it-from-scripts-and-other-programs) and [in Go](USAGE.md#using-it-in-go)

## Using it in Go

```console
go get github.com/Knight1/vanmoof-certificates/vanmoof
```

```go
s, err := vanmoof.Login(email, password)
bikes, err := s.Bikes()
cert, err := s.RequestCertificate(bikes[0], publicKey)

res := vanmoof.CheckCertificate(cert, vanmoof.Expect{PublicKey: publicKey, Bike: &bikes[0]})
if !res.Valid {
	log.Println(res.Errors)
}
```

USAGE.md has [a complete example](USAGE.md#using-it-in-go), and [pkg.go.dev](https://pkg.go.dev/github.com/Knight1/vanmoof-certificates/vanmoof) (or `go doc -all github.com/Knight1/vanmoof-certificates/vanmoof`) the whole package.

## Certificate Structure

VanMoof bike certificates use a binary format consisting of an Ed25519 signature followed by a CBOR-encoded payload.

**Key Format (as used in crypto.go):**
- **Private key**: 64 bytes in base64 encoding (Ed25519 seed concatenated with public key)
- **Public key**: 32 bytes in base64 encoding (raw Ed25519 public key)
- **Encoding**: Standard base64 (`base64.StdEncoding` in Go)
- **No additional prefixes**: Unlike some implementations, this uses raw keys without metadata

**Important Notes:**
- Some implementations may prefix the public key with 0x00 (33 bytes total) - this is also accepted
- The private key from `ed25519.GenerateKey()` is 64 bytes: 32-byte seed + 32-byte public key

### Overall Format

```
[64 bytes: Ed25519 Signature] + [Variable length: CBOR Payload]
```

### Signature (64 bytes)

The first 64 bytes contain an Ed25519 signature that cryptographically signs the CBOR payload:

- **Bytes 0-31**: R component of the Ed25519 signature
- **Bytes 32-63**: S component of the Ed25519 signature

This signature is created by VanMoof's Certificate Authority (CA) and can be verified using the CA's public key to ensure the certificate is authentic and hasn't been tampered with.

The CA signing public key (recovered from the bike's BLE certificate, and the same across all certificates) is:

```
29b1f31c07d1c63b124057ebe75a0bc0796259722e5dd9a9a9302ae2061184a0
```

Every parsed certificate's signature is verified against this key; a mismatch is
flagged as an error (silent on success). Run with `-debug` for full verification detail.
No S6 signing key is known yet, so S6 certificates are reported with the signature not verified.

### CBOR Payload Structure

Starting at byte 64, the certificate contains a CBOR-encoded map with the following fields:

| Key | Type | Description | Example |
|-----|------|-------------|---------|
| `i` | uint32 | Certificate ID | `1337` |
| `f` | string | Frame Module serial number (AFM - Authorized Frame Module) | `"SVTBKLdddddOA"` |
| `b` | string | Bike Module serial number (ABM - Authorized Bike Module) | `"SVTBKLdddddOA"` |
| `e` | uint32 | Certificate expiry (Unix timestamp) | `1767668550` |
| `r` | uint8 | Role/Access level (7-66) | `7` |
| `u` | bytes[16] | User UUID (without hyphens) | `uuid3` |
| `p` | bytes[32] | User's Ed25519 public key | 32-byte public key |

The tool reports a certificate as invalid if a field is missing, appears twice, has the wrong type, or holds a number too big for its type (such as an expiry after 2106). It doesn't guess at such a certificate: the bike might read it differently than the tool would show it.

### Access Levels (Role Field)

The `r` (role) field determines what permissions the certificate grants by assigned the following username "Access Level" to the process accessing the MQTT Broker on the Bike.
More information here [acl.txt](https://github.com/Knight1/vanmoof-s5-decomp/blob/main/main/docs/acl.txt)

| Value | Access Level | Description |
|-------|--------------|-------------|
| `0x07` | Owner | Standard access |
| `0x0B` | Guest | Restricted access, for a bike shared with you |
| `0x11` | Bike Doctor | Full access |
| `0x16` | Bike Hunter | Full access |
| `0x37` | QA Engineer | Full access |
| `0x42` | R&D Engineer | Full access |

Any other role is shown as unknown, with a warning.

### Certificate Binding

The certificate cryptographically binds together:

1. **Specific Bike**: frame/bike module serials (`f`, `b`)
2. **Certificate ID**: The `i` field varies per certificate
3. **Specific User**: API user UUID (`u`)
4. **Specific Public Key**: user's Ed25519 public key (`p`)
5. **Access Level**: role field (`r`)
6. **Validity Period**: expiry timestamp (`e`)

When a bike validates a certificate, it verifies:
- The Ed25519 signature is valid (signed by VanMoof CA)
- The frame/bike module serials match this bike
- The certificate hasn't expired
- The user's public key matches the one in the certificate

### Example Certificate Breakdown

Decoded structure:
- **Signature**: `...` (64 bytes)
- **Certificate ID**: `1337`
- **Frame Module Serial (AFM)**: `SVTBKLdddddOA`
- **Bike Module Serial (ABM)**: `SVTBKLdddddOA`
- **Expiry**: `1767668550` (January 6, 2026 04:02:30 CET)
- **Role**: `7` (Owner)
- **User UUID**: `11111111-1111-3111-8111-111111111111` (UUIDv3)
- **Public Key**: `KIQtqMxZ9Vdj3YLfNgNHjUB4WN4gLtDX/FwpiyFiUMs=`

### CBOR Encoding Details

The payload uses CBOR (Concise Binary Object Representation, RFC 8949) encoding:

```
0xa7                    # Map with 7 entries
  0x61 0x69             # Text string "i"
  0x19 0x05 0x39        # uint16: 1337 (Certificate ID; a bigger one takes 0x1a + 4 bytes)
  
  0x61 0x66             # Text string "f" 
  0x6d                  # Text string, 13 bytes
  "SVTBKLdddddOA"       # Frame Module serial (AFM)
  
  0x61 0x62             # Text string "b"
  0x6d                  # Text string, 13 bytes  
  "SVTBKLdddddOA"       # Bike Module serial (ABM)
  
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

- It seems that there is no revocation nor public logging. If someone has access to the VanMoof account with your bike, they can generate certificates without you noticing. Furthermore, these certificates are irrevocable. So the only way to secure the bike would be to lock it in the garage or basement until 7 days have passed.
- It is currently not known how the bike knows the time after a power loss. This would be either via GSM, GPS, or the phone. What happens if a jammer is in place or if the GPS time was spoofed is currently unknown. In the case where you can spoof an older time, you could in theory unlock the bike with an older certificate if the bike accepts the new time as the "correct time".
- What happens after 7 days? Since VanMoof reverted the 10-year certificate lifetime, it is currently not possible to control the bike (besides the backup code) without talking to the VanMoof API to issue a new certificate. Alternatively, logic could be implemented where 2FA is required to issue a certificate valid for more than 7 days.
- Also VanMoof can lock you out at any time. 
