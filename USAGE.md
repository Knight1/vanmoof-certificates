# vanmoof-certificates

## Installation

```console
git clone https://github.com/Knight1/vanmoof-certificates.git
cd vanmoof-certificates
CGO_ENABLED=0 go build -mod=vendor -ldflags "-w -d"
```

This builds a static binary (`-d` needs cgo off). On Windows, build with `go build -mod=vendor -ldflags "-w"`.

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-email` | VanMoof email address | Prompt if not provided |
| `-bikes` | Bikes to process: 'all', bike IDs or frame numbers (comma-separated), or 'ask' | `all` |
| `-show-keys` | Show BLE encryption keys instead of requesting certificates: `static` (only the keys) or `all` (keys, plus certificates for the certificate bikes) | - |
| `-debug` | Enable debug output (tokens and keys stay hidden) | `false` |
| `-redact` | Hide secrets and personal data in all output, to share it in an issue or pull request | `false` |
| `-show-everything` | With `-debug`, also show the tokens and keys it hides. Never share this output | `false` |
| `-no-cache` | Do not read or write token cache | `false` |
| `-sudo` | Skip all validation checks | `false` |
| `-cert` | Base64 encoded certificate to parse | - |
| `-pubkey` | Base64 encoded public key (optional) | - |
| `-framenumber` | Frame number to verify a `-cert` certificate against (optional) | - |
| `-genkey` | Generate Ed25519 key pair and exit | - |
| `-version` | Print version information | - |

## Exit Status

| Status | Meaning |
|--------|---------|
| `0` | Success, also when there was nothing to do (e.g. no supported bikes) |
| `1` | Something failed: logging in, getting your bikes, a certificate request, or a certificate check (`Certificate INVALID`) |
| `2` | Invalid flags or flag values |

Optional lookups (bikes shared with you, pending sharing invitations, bike messages) don't change the exit status: if one fails, the tool prints a warning and carries on.

## Requirements

- Go 1.25 or later. Builds use at least Go 1.27.2, for its security fixes; an older `go` downloads it automatically
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
1. Reuse the app token if it and the auth token are still valid (~2 hours)
2. Refresh the app token using the auth token if needed (~1 year validity)
3. Use the refresh token if the auth token has expired (storing the new refresh token if the server issues one)
4. Only prompt for password if all cached tokens are expired or rejected

Cached tokens are only checked for expiry locally. If the server rejects them before they expire (e.g. after a password change), the tool logs in again, with the refresh token first and then the password, and replaces them in the cache.

To encrypt the token cache, set the `VANMOOF_CACHE_KEY` environment variable:

```console
export VANMOOF_CACHE_KEY="your-secret-passphrase"
./vanmoof-certificates -email user@vanmoof.com
```

This encrypts the cache file with AES-256-GCM (PBKDF2-SHA256 key derivation, 600k iterations). Without the env var, the cache is stored as plain JSON, which the tool points out when it creates the file. An existing unencrypted cache is encrypted the first time the tool runs with the variable set, and one encrypted by an earlier version (100k iterations) is re-encrypted the first time it's read. The cache file is replaced in one step, so an interrupted run can't leave it half-written.

If the cache can't be read (it's encrypted and `VANMOOF_CACHE_KEY` is missing or wrong, or the file is corrupt), the tool warns, logs in without it and leaves the file as it is, so no account's tokens are lost. Set the right key again, or delete the file to start over.

To disable token caching entirely:

```console
./vanmoof-certificates -email user@vanmoof.com -no-cache
```

To remove the cached tokens of all accounts, delete `~/.vanmoof-certificates/tokens.json`.


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

Each bike is processed once, even if it's listed twice, e.g. by ID and by frame number.

### Show BLE Encryption Keys

Bikes older than the S5 (S2/S3/S4 and earlier) authenticate over BLE with a key
instead of a certificate. It is returned as `key.encryptionKey` by `getCustomerData`.

**Only the keys of S2/S3/S4 and older bikes (no certificates):**
```console
./vanmoof-certificates -email user@vanmoof.com -show-keys static
```

**Keys, then certificates for S5/A5 and S6 as usual:**
```console
./vanmoof-certificates -email user@vanmoof.com -show-keys all
```

Both modes list every non-certificate bike, whether or not the API has returned a key yet
(`bleSecret: not available` if not). `all` additionally runs the regular certificate flow afterwards,
including `-pubkey`, for S5/A5 and S6. `-bikes` applies to both parts; S5/A5 and S6 only appear in the
certificate part, since they have no BLE key.

Output per bike:
```
bikeName: Wooosh
frameNumber: ASY0000000
macAddress: 00:11:22:33:44:55
bleSecret: 00112233445566778899aabbccddeeff
```

**Keep the BLE secret private.** Anyone who has it can control the bike over Bluetooth.

If a bike has no key yet and isn't S5/A5 or S6 (every older generation authenticates with a static
key, not just a handful of known profiles), the key may still be on its way as a bike message queued
for delivery the next time the bike connects over BLE (`getBikeMessages`).
In that case an extra line is printed:
```
bikeMessage: 1 message(s) waiting for delivery over BLE
```
or, if nothing is queued:
```
bikeMessage: none waiting
```
If a bike message is waiting either sent it to the bike via a tool or use the official app.  

### Debug Mode

Enable debug output to see detailed API requests and responses:

```console
./vanmoof-certificates -email user@vanmoof.com -debug
```

Debug output hides secrets: tokens, the refresh token, BLE keys and bike messages
in API responses. It still contains personal data, such as your email address,
names and frame numbers, and the regular output, such as a generated private key
or a `-show-keys` BLE key.

To share output, for example in an issue or pull request, add `-redact`. It hides
secrets and personal data in all output, including the private key, BLE keys and
certificates. Frame numbers and IDs keep only their shape (e.g. `LLLLLLDDDDDLL`):

```console
./vanmoof-certificates -email user@vanmoof.com -debug -redact
```

To see everything, tokens included, add `-show-everything` (debug only). Never
share that output: anyone with your tokens or keys can unlock your bike.

The certificate's Ed25519 signature is always verified against VanMoof's known
certificate signing (CA) key. In normal mode this is silent — a mismatch is
reported as an error, a valid signature prints nothing. Debug mode additionally
shows the full signature validation detail.

No S6 signing key is known yet, so S6 certificates are reported as
`Certificate valid, but signature not verified` instead. When requesting
certificates, the bike's BLE profile tells an S6 apart; offline (`-cert`) only
the frame number can, and some SA5 frame numbers look like S6 ones. Warnings,
such as an expiry more than a year away or an unknown role, are listed under
the result even when the certificate is valid.


### Parse Existing Certificate

Parse a certificate without fetching from API:

```console
./vanmoof-certificates -cert "BASE64_CERTIFICATE_STRING"
```

With optional public key and frame number verification:

```console
./vanmoof-certificates -cert "BASE64_CERT" -pubkey "BASE64_PUBKEY" -framenumber "FRAME_NUMBER"
```

Certificates the tool requests itself are always checked against the bike they were requested for.

Control characters in a certificate (or in names and messages from the API) are shown
escaped, e.g. `\x1b`, so a crafted certificate can't change how the result looks.

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

## Using it from Scripts and Other Programs

Other programs use the tool by running it: the exit status says whether everything
worked, and the output contains the certificate. The Go code is in `internal/`, so
other Go modules can't import it.

### Run it without prompts

- Pass `-email`, and the password in `VANMOOF_PASSWORD`. After the first login the
  token cache logs in without it (see [Token Caching](#token-caching)); in throwaway
  environments, such as CI, add `-no-cache`.
- Pick bikes with `-bikes` (IDs or frame numbers), not `ask`.
- Use your own key pair: create it once with `-genkey`, keep the private key safe, and
  request certificates with `-pubkey`. Every certificate then works with that private
  key, and the output contains no private key.

If it needs the password but has neither `VANMOOF_PASSWORD` nor a terminal to ask on,
it exits with status `1` instead of waiting.

### Read the result

The exit status is `0` if every certificate was obtained and is valid, `1` if not (or
logging in failed), and `2` for invalid flags (see [Exit Status](#exit-status)). Errors go to
standard output, like everything else.

For each bike, the line after `Certificate:` is VanMoof's JSON response, and its
`certificate` field holds the certificate:

```
Bike ID: 1337
Name: My bike
Frame number: LLLLLLDDDDDLL
Model: SA5
Certificate:
{"certificate":"BASE64_ENCODED_CERTIFICATE"}
Parsing certificate...
Certificate valid: LLLLLLDDDDDLL, Owner, expires 2026-01-06 04:02:30 CET, bike matched, pubkey ok, user ok
```

Check the exit status rather than parsing the `Certificate valid` line, and leave out
`-debug`: it adds a lot of output, including personal data.

Shell, with [jq](https://jqlang.org/):

```sh
out=$(VANMOOF_PASSWORD="$PASSWORD" ./vanmoof-certificates -email user@vanmoof.com -bikes 1337 -pubkey "$PUBKEY") || exit 1
certificate=$(printf '%s\n' "$out" | awk 'previous == "Certificate:" { print; exit } { previous = $0 }' | jq -r .certificate)
```

Python:

```python
import json, os, subprocess

result = subprocess.run(
    ["./vanmoof-certificates", "-email", "user@vanmoof.com", "-bikes", "1337", "-pubkey", pubkey],
    env={**os.environ, "VANMOOF_PASSWORD": password},
    capture_output=True, text=True,
)
if result.returncode != 0:
    raise RuntimeError(f"vanmoof-certificates exited with {result.returncode}:\n{result.stdout}")
lines = result.stdout.splitlines()
certificate = json.loads(lines[lines.index("Certificate:") + 1])["certificate"]
```

To check a certificate you already have, use the exit status of `-cert`:

```sh
if ./vanmoof-certificates -cert "$CERTIFICATE" -pubkey "$PUBKEY" -framenumber "$FRAME_NUMBER"; then
    echo "valid"
fi
```

The output contains your certificate, and without `-pubkey` also a new private key:
keep it out of shared logs. `-redact` hides both, so use it only for output you want
to share, not when you need the certificate.
