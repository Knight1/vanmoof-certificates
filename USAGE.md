# vanmoof-certificates

## Installation

```console
git clone https://github.com/Knight1/vanmoof-ble.git
go build -mod=vendor -ldflags "-w -d"
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-email` | VanMoof email address | Prompt if not provided |
| `-bikes` | Bikes to process: 'all', IDs (comma-separated), or 'ask' | `all` |
| `-debug` | Enable debug output | `false` |
| `-no-cache` | Do not read or write token cache | `false` |
| `-sudo` | Skip all validation checks | `false` |
| `-cert` | Base64 encoded certificate to parse | - |
| `-pubkey` | Base64 encoded public key (optional) | - |
| `-bikeid` | Bike ID for verification (optional) | - |
| `-genkey` | Generate Ed25519 key pair and exit | - |
| `-version` | Print version information | - |

## Requirements

- Go 1.24 or later
- VanMoof account with registered SA5/S6 bike(s), or shared bike access (guest invitations)

## Example Output

```
Privkey = ✂️
Pubkey = Yd2bYMB3+vs4cCnDtPbcaM164KIl2zs05AK2jt/K6Gs=

Bike ID: 1337
Frame number: LLLLLLDDDDDLL
Model: SA5 (ELECTRIFIED_2022)
Certificate:
-----------
{"certificate":"BASE64_ENCODED_CERTIFICATE"}
-----------

Parsing certificate...
Certificate valid: LLLLLLDDDDDLL, Owner (Full Control), expires 2026-01-06 04:02:38 CET, bike matched, pubkey ok, user ok
```

## Usage

### Interactive Mode

Run without any flags to be prompted for credentials:

```console
./vanmoof-certificates
```

This will:
1. Prompt for your VanMoof email
2. Use cached tokens if available, otherwise prompt for your password (hidden input)
3. Fetch all owned SA5/S6 bikes and shared bikes (guest access) and generate certificates

### Token Caching

Tokens are cached in `~/.vanmoof-certificates/tokens.json` (file permissions `0600`). Multiple accounts are supported — each email's tokens are stored independently. On subsequent runs, the tool will:
1. Reuse the app token if still valid (~2 hours)
2. Refresh the app token using the auth token if needed (~1 year validity)
3. Use the refresh token if the auth token has expired
4. Only prompt for password if all cached tokens are expired

To encrypt the token cache, set the `VANMOOF_CACHE_KEY` environment variable:

```console
export VANMOOF_CACHE_KEY="your-secret-passphrase"
./vanmoof-certificates -email user@vanmoof.com
```

This encrypts the cache file with AES-256-GCM (PBKDF2-SHA256 key derivation, 100k iterations). Without the env var, the cache is stored as plain JSON.

To disable token caching entirely:

```console
./vanmoof-certificates -email user@vanmoof.com -no-cache
```


### Command-Line Mode

Provide email via flag (and optionally set `VANMOOF_PASSWORD` environment variable):

```console
./vanmoof-certificates -email user@vanmoof.com
```

#### Request a certificate with your own public key

If you want to use your own Ed25519 public key (instead of generating a new one), supply it with the `-pubkey` flag:

```console
./vanmoof-certificates -email user@vanmoof.com -pubkey <BASE64_PUBKEY>
```

This will request a certificate for your bike(s) using the provided public key. No private key will be generated or printed in this mode.

### Select Specific Bikes

**Process all bikes (default):**
```console
./vanmoof-certificates -email user@vanmoof.com -bikes all
```

**Process specific bikes by ID:**
```console
./vanmoof-certificates -email user@vanmoof.com -bikes 42,1337
```

**Process shared bikes by frame number:**
```console
./vanmoof-certificates -email user@vanmoof.com -bikes {Framenumber}
```

**Interactive bike selection:**
```console
./vanmoof-certificates -email user@vanmoof.com -bikes ask
```

This will display your owned and shared bikes and prompt you to select which ones to process.

### Debug Mode

Enable debug output to see detailed API requests and responses:

```console
./vanmoof-certificates -email user@vanmoof.com -debug
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

### Generate Ed25519 Key Pair

Generate a new Ed25519 key pair and exit (useful for creating keys to reuse):

```console
./vanmoof-certificates -genkey
```

This will output:
```
Privkey = <base64-encoded-private-key>
Pubkey = <base64-encoded-public-key>
```

You can then use the public key when requesting certificates from the API by providing it via the tool, and save both keys for later use.

### Manually Generate Ed25519 Key Pair

If you want to use the same unlock key every time you request a new Certificate you need to generate your own Ed25519 key pair instead of using the tool's automatic generation. The easiest method is to use the `-genkey` flag (see above), or you can use one of these alternative methods:

**Using OpenSSL:**
```console
# Generate private key
openssl genpkey -algorithm ED25519 -out private.pem

# Extract public key
openssl pkey -in private.pem -pubout -out public.pem

# For private key (64 bytes total):
# The last 64 bytes of the DER format contain: 32-byte seed + 32-byte public key
openssl pkey -in private.pem -traditional -outform DER 2>/dev/null | tail -c 64 | base64

# For public key (32 bytes):
# Extract the raw 32-byte public key from DER format
openssl pkey -in public.pem -pubin -outform DER | tail -c 32 | base64
```