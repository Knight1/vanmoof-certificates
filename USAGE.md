# vanmoof-certificates

## Installation

```console
git clone https://github.com/Knight1/vanmoof-certificates.git
cd vanmoof-certificates
CGO_ENABLED=0 go build -mod=vendor -ldflags "-w -d"
```

This builds a static binary (`-d` needs cgo off). On Windows, build with `go build -mod=vendor -ldflags "-w"`.

Or install it without cloning: `go install github.com/Knight1/vanmoof-certificates@latest`
puts it into `$(go env GOPATH)/bin`.

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-email` | VanMoof email address | Prompt if not provided |
| `-bikes` | Bikes to process: 'all', bike IDs or frame numbers (comma-separated), or 'ask' | `all` |
| `-show-keys` | Show BLE encryption keys instead of requesting certificates: `static` (only the keys) or `all` (keys, plus certificates for the certificate bikes) | - |
| `-debug` | Enable debug output (tokens and keys stay hidden) | `false` |
| `-redact` | Hide secrets and personal data in all output, to share it in an issue or pull request | `false` |
| `-show-everything` | With `-debug`, also show the tokens and keys it hides. Never share this output | `false` |
| `-new-key` | Request the certificates for a new key pair, which replaces the saved one (see [Cache](#cache)) | `false` |
| `-show-saved` | Show what the cache holds for the account: key pair, certificates, BLE keys, bike messages and customer data | `false` |
| `-cleartext-keys` | Without `VANMOOF_CACHE_KEY`, save the key pair, certificates, BLE keys and customer data unencrypted (see [Cache](#cache)) | `false` |
| `-no-cache` | Do not read or write the cache (tokens, key pair, certificates, BLE keys, bike messages, customer data) | `false` |
| `-allow-unknown-revocation` | Connect even when a VanMoof server's TLS certificate can't be confirmed unrevoked — neither OCSP nor the CRL vouches for it, or Mozilla's OneCRL couldn't be fetched; a revoked one is always refused (see [TLS Certificate Revocation](#tls-certificate-revocation)) | `false` |
| `-invitations` | Bike sharing invitations: `list`, `accept` or `decline` them (see [Bike Sharing Invitations](#bike-sharing-invitations)) | - |
| `-sudo` | Skip all validation checks | `false` |
| `-cert` | Base64 encoded certificate to parse | - |
| `-pubkey` | Base64 encoded public key (optional) | - |
| `-framenumber` | Frame number to verify a `-cert` certificate against (optional) | - |
| `-genkey` | Generate Ed25519 key pair and exit | - |
| `-generate` | Generate a self-signed certificate from a JSON config file and exit (advanced, see [Generate your own certificate](#generate-your-own-certificate-advanced)) | - |
| `-version` | Print version information | - |

## Exit Status

| Status | Meaning |
|--------|---------|
| `0` | Success, also when there was nothing to do (e.g. no supported bikes) |
| `1` | Something failed: logging in, getting your bikes, a certificate request, a certificate check (`Certificate INVALID`), or accepting or declining an invitation. That includes a VanMoof server the tool refused, as its TLS certificate is revoked or can't be confirmed not to be |
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
Name: My bike
Frame number: LLLLLLDDDDDLL
Model: SA5
Certificate:
{"certificate":"BASE64_ENCODED_CERTIFICATE"}
Parsing certificate...
Certificate valid: LLLLLLDDDDDLL, Owner, expires 2026-01-06 04:02:30 CET, bike matched, pubkey ok, user ok
```

Later runs request the certificates for the same key pair, and say so above it:
`Using the saved key pair (-new-key makes a new one)` (see [Cache](#cache)).

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

### Cache

The tool keeps what it gets in `~/.vanmoof-certificates` (file permissions `0600`), for each account (email address) separately:

| File | What it holds |
|------|---------------|
| `tokens.json` | The tokens, to log in without the password |
| `bikes.json` | The key pair the certificates are requested for, and for each bike its latest valid certificate (with the key pair it's for), its BLE key (S4 and older), and the bike messages `-show-keys` found waiting for it |
| `customer_data.json` | The account's `getCustomerData` response |

The certificates are requested for the saved key pair, so a BLE app needs its private key
only once. `-new-key` makes a new key pair, which replaces the saved one, and requests the
certificates for it:

```console
./vanmoof-certificates -email user@vanmoof.com -new-key
```

`-show-saved` shows what's saved for the account, keys included, without contacting
VanMoof. Add `-redact` to hide the keys and personal data:

```console
./vanmoof-certificates -email user@vanmoof.com -show-saved
```

With the cached tokens, on subsequent runs, the tool will:
1. Reuse the app token if it and the auth token are still valid (~2 hours)
2. Refresh the app token using the auth token if needed (~1 year validity)
3. Use the refresh token if the auth token has expired (storing the new refresh token if the server issues one)
4. Only prompt for password if all cached tokens are expired or rejected

Cached tokens are only checked for expiry locally. If the server rejects them before they expire (e.g. after a password change), the tool logs in again, with the refresh token first and then the password, and replaces them in the cache.

`bikes.json` holds your private key and BLE keys: anyone who has them can unlock your
bikes. To encrypt the cache, set the `VANMOOF_CACHE_KEY` environment variable:

```console
export VANMOOF_CACHE_KEY="your-secret-passphrase"
./vanmoof-certificates -email user@vanmoof.com
```

This encrypts the cache files with AES-256-GCM (PBKDF2-SHA256 key derivation, 600k iterations).

Without the env var, the tokens are stored as plain JSON, which the tool points out when
it creates the file. The key pair, certificates, BLE keys and customer data aren't saved
unencrypted unless you accept that with `-cleartext-keys`, which every run that should
save them needs; without it, each run makes a new key pair. What's saved is used either
way.

 An existing unencrypted file is encrypted the first time the tool runs with the variable set, and one encrypted by an earlier version (100k iterations) is re-encrypted the first time it's read. Each file is replaced in one step, so an interrupted run can't leave it half-written.

If a cache file can't be read (it's encrypted and `VANMOOF_CACHE_KEY` is missing or wrong, or the file is corrupt), the tool warns, carries on without it (logging in with the password, or making a new key pair) and leaves the file as it is, so no account's data is lost. Set the right key again, or delete the file to start over.

To neither read nor write the cache, so that every run also makes a new key pair:

```console
./vanmoof-certificates -email user@vanmoof.com -no-cache
```

To remove the cached tokens of all accounts, delete `~/.vanmoof-certificates/tokens.json`;
to remove everything the tool has saved, delete the whole folder.


### Command-Line Mode

Provide email via flag (and optionally set `VANMOOF_PASSWORD` environment variable):

```console
./vanmoof-certificates -email user@vanmoof.com
```

#### Request a certificate with your own public key

If you want to use your own Ed25519 public key (instead of the tool's saved key pair), supply it with the `-pubkey` flag:

```console
./vanmoof-certificates -email user@vanmoof.com -pubkey <BASE64_PUBKEY>
```

This will request a certificate for your bike(s) using the provided public key. No private key will be generated or printed in this mode, and the saved key pair stays as it is; the certificates are saved without a private key.

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

### Bike Sharing Invitations

When someone shares their bike with you, the tool warns about the pending invitation.
List the invitations, and accept or decline them:

```console
./vanmoof-certificates -email user@vanmoof.com -invitations list
./vanmoof-certificates -email user@vanmoof.com -invitations accept
./vanmoof-certificates -email user@vanmoof.com -invitations decline
```

Each invitation is listed like this:

```
Invitation 1
Bike: Their bike
Model: SA5
Owner: Their name
Expires: 2026-12-24T12:00:00+0100
GUID: 0f0f0000-0000-3000-8000-000000000000
```

`accept` and `decline` then ask which ones: their numbers or GUIDs, comma-separated, or
`all`. To choose them without the question, e.g. in a script, put them after `=`:

```console
./vanmoof-certificates -email user@vanmoof.com -invitations accept=all
./vanmoof-certificates -email user@vanmoof.com -invitations decline=0f0f0000-0000-3000-8000-000000000000
```

Once you've accepted, the bike is shared with you: run the tool as usual to request its
certificate.

### Debug Mode

Enable debug output to see detailed API requests and responses:

```console
./vanmoof-certificates -email user@vanmoof.com -debug
```

Debug output hides secrets: tokens, the refresh token, BLE keys and bike messages
in API responses. It still contains personal data, such as your email address,
names and frame numbers, and the regular output, such as the private key, a
`-show-keys` BLE key, or what `-show-saved` shows.

To share output, for example in an issue or pull request, add `-redact`. It hides
secrets and personal data in all output, including the private key, BLE keys and
certificates. Frame numbers and IDs keep only their shape (e.g. `LLLLLLDDDDDLL`):

```console
./vanmoof-certificates -email user@vanmoof.com -debug -redact
```

To see everything, tokens included, add `-show-everything` (debug only). Never
share that output: anyone with your tokens or keys can unlock your bike.

Debug output lists the account's bikes with their name and BLE profile. A bike
shared with you shows how long it's shared (times in UTC): one from `getCustomerData`
(such as an S3, with a role other than `owner`) with its role, and one from the
Vehicle Registry API (S5/S6) with its owner:

```
[DEBUG] Retrieved 2 bikes: 1 owned, 1 shared with you
[DEBUG]   SVTBKL00001OA "My bike": ELECTRIFIED_2022 (SA5)
[DEBUG]   ASY0000002 "Borrowed S3": ELECTRIFIED_2020 (S3/X3), shared with you as user until 2026-11-03 15:04 UTC (7 days left)
[DEBUG] Retrieved 1 shared vehicles
[DEBUG]   SVTBKL00003OA "Their bike": ELECTRIFIED_2025 (S6), shared by Alice until 2026-12-01 12:00 UTC (35 days left)
```

A sharing that hasn't started yet shows `from` its start, one without an end
`without end`, and one that's over `(expired)`. `-redact` hides the names, and any
time that isn't in the usual format.

Debug output also shows, once for each, what the revocation checks found out about
the TLS certificates of VanMoof's servers (see [TLS Certificate Revocation](#tls-certificate-revocation)):

```
[DEBUG] TLS certificate api.vanmoof-api.com (OCSP: good, stapled; CRL: good): not revoked
```

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


### TLS Certificate Revocation

Before the tool sends anything to one of VanMoof's servers, such as your password or a
token, it checks that the server's TLS certificate and the CA certificates it chains to
aren't revoked: with OCSP (the response the server staples, or else the CA's responder),
with the CA's CRL, and against Mozilla's OneCRL. A certificate that any of them reports
revoked is refused, as someone may be using its stolen key. Each certificate is checked
once per run, and the connections stay open, so this adds a few requests, not one per
request to VanMoof.

The tool asks whichever OCSP responder and CRL each certificate names, so it keeps working
when VanMoof's servers change CA (they use Amazon's and Let's Encrypt's now, the latter
without OCSP). A certificate valid for 7 days at most that names neither, as a CA may
issue it, has nothing of its own to check.

OneCRL is the list of certificates and keys Firefox distrusts, which the tool fetches once
a run from [Firefox Remote Settings](https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records).
It matters because OCSP and the CRL come from the CA itself: a CA whose key is compromised
can sign a certificate for `api.vanmoof-api.com` and vouch for it, but it can't take itself
off Firefox's list. The list only ever distrusts, so a certificate it doesn't name is not
thereby confirmed good — its OCSP or CRL still has to.

A certificate that neither OCSP nor the CRL confirms, e.g. as the CA's servers can't be
reached, or whose OneCRL couldn't be fetched, is refused too:

```
Error: authentication failed: Post "https://api.vanmoof-api.com/v8/authenticate": vanmoof: TLS certificate revocation unknown: api.vanmoof-api.com (OCSP: …; CRL: …; OneCRL: …); -allow-unknown-revocation connects anyway
```

`-allow-unknown-revocation` connects anyway, unless OCSP, the CRL or OneCRL reports the
certificate revoked. Only use it while the CA's or Mozilla's servers can't be reached:
someone who blocks them could otherwise use a revoked or distrusted certificate.

An OCSP request tells the CA which of its certificates you check, as a browser's does; a
stapled response, the CRL and OneCRL don't.

### Memory hardening

On Linux, before it handles any secret, the tool keeps them off disk, best-effort:

- It locks all of its memory into RAM (`mlockall`), so keys, tokens and your password
  aren't written to swap.
- It sets the core-dump size to zero, so a crash can't write memory to a core file.

It locks the whole process because Go moves stacks and copies strings around, so an
individual secret can't be locked on its own. For the same reason, secrets held as text
(tokens, your password, `VANMOOF_CACHE_KEY`) can't be wiped after use; the tool does clear
the key material it derives (the cache key, a signing key) once it's done with it, as
defense in depth.

`mlockall` needs enough `RLIMIT_MEMLOCK`, which an unprivileged user often lacks. If it
can't lock memory, it prints a warning and carries on:

```
WARNING: couldn't lock memory to keep secrets out of swap: cannot allocate memory (raise the limit with 'ulimit -l', or ignore if this system has no swap)
```

Raise the limit (`ulimit -l unlimited` as root, or a `memlock` entry in
`/etc/security/limits.conf`), or ignore it on a system without swap. macOS and Windows
builds don't harden memory yet.

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

A certificate is invalid if a field is missing, appears twice, has the wrong type, or
holds a number too big for its type (such as an expiry after 2106): the bike might
read it differently than the tool would show it.

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

You can then use the public key when requesting certificates from the API by providing it via the tool, and save both keys for later use. The tool doesn't keep this key pair in its cache.

### Manually Generate Ed25519 Key Pair

The tool uses its saved key pair for every certificate (see [Cache](#cache)). To use a key pair of your own instead, for example one that never leaves your device, generate it with the `-genkey` flag (see above) or one of these alternative methods, and pass its public key with `-pubkey`:

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

### Generate your own certificate (advanced)

> **This is for a bike whose module firmware you have changed to trust your own signing
> key.** A stock VanMoof bike trusts only VanMoof's signing key and ignores a certificate
> from here. It needs an opened bike module and reflashed firmware; on an untouched bike it
> does nothing.

Normally VanMoof's CA signs the certificates (with `-email`, above). `-generate` instead
signs one with a key of your own, so you run your own CA for a bike you've reflashed to
trust it. It uses no account and no network:

```console
./vanmoof-certificates -generate config.json
```

The config is a JSON file:

```json
{
  "signing_key": "<base64 Ed25519 private key that signs, e.g. from -genkey>",
  "public_key": "<base64 Ed25519 public key to authorize; the signing key's own if left out>",
  "afm": "SVTBKL00000OA",
  "abm": "SVTBKL00000OA",
  "role": "Owner",
  "user_uuid": "11111111-1111-4111-8111-111111111111",
  "validity_days": 7
}
```

| Field | What it is |
|-------|------------|
| `signing_key` | The Ed25519 private key that signs the certificate: the 64-byte key `-genkey` prints, or a 32-byte seed. The bike's firmware has to trust its public half. Keep it secret |
| `public_key` | The Ed25519 public key the certificate authorizes, which then unlocks the bike. Defaults to `signing_key`'s own public half, to authorize your own key |
| `afm` | The frame module (AFM), normally the frame number |
| `abm` | The bike module (ABM). Defaults to `afm` |
| `role` | The access level: a name (`Owner`, `Guest`, `Bike Doctor`, `Bike Hunter`, `QA Engineer`, `R&D Engineer`) or a number (`7`, `0x42`); see [Access Levels](README.md#access-levels-role-field) |
| `user_uuid` | The user's UUID, hyphenated or not |
| `validity_days` | Days from now until it expires. Use `expires` instead for an exact time (RFC 3339, e.g. `2027-01-02T15:04:05Z`) |
| `id` | The certificate's ID; a random one if left out |

It prints the fields it put in and the certificate:

```
Generated a self-signed certificate (it works only on a bike whose firmware trusts your signing key):
  AFM (frame module):   SVTBKL00000OA
  ABM (bike module):    SVTBKL00000OA
  Access level:         Owner
  ...
Certificate:
<base64 certificate>
```

The certificate is a secret, like a private key: with the authorized private key it unlocks
the bike. `-redact` hides it (along with the keys and frame numbers), so generate the one
you'll use **without** `-redact`, and add it only to share the output.

`-cert` checks a certificate from here against VanMoof's signing key, so it reports the
signature as not VanMoof's. That's expected: your bike checks it against your key.

## Using it from Scripts and Other Programs

Other programs use the tool by running it: the exit status says whether everything
worked, and the output contains the certificate. Go programs can import its package
instead and get the results as values: see [Using it in Go](#using-it-in-go).

### Run it without prompts

- Pass `-email`, and the password in `VANMOOF_PASSWORD`. After the first login the
  cache logs in without it (see [Cache](#cache)); in throwaway environments, such as
  CI, add `-no-cache`.
- Pick bikes with `-bikes` (IDs or frame numbers), not `ask`.
- The certificates are all requested for the saved key pair, so they work with the same
  private key. To keep the private key out of the tool and its output, create a key
  pair once with `-genkey`, keep the private key safe, and request certificates with
  `-pubkey`.

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

The output contains your certificate, and without `-pubkey` also the private key:
keep it out of shared logs. `-redact` hides both, so use it only for output you want
to share, not when you need the certificate.

## Using it in Go

The package `github.com/Knight1/vanmoof-certificates/vanmoof` does what the tool does,
but returns the results instead of printing them:

```console
go get github.com/Knight1/vanmoof-certificates/vanmoof
```

```go
package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/Knight1/vanmoof-certificates/vanmoof"
)

func main() {
	// The public key of your own key pair, e.g. from -genkey: keep the private key safe
	publicKey := os.Getenv("PUBKEY")

	s, err := vanmoof.Login("user@vanmoof.com", os.Getenv("VANMOOF_PASSWORD"))
	if err != nil {
		log.Fatal(err)
	}
	bikes, err := s.Bikes()
	if err != nil && !errors.Is(err, vanmoof.ErrSharedBikes) {
		log.Fatal(err)
	}

	for i, bike := range bikes {
		if !bike.UsesCertificates() {
			continue // an S4/X4 or older bike, which uses a BLE key instead
		}
		cert, err := s.RequestCertificate(bike, publicKey)
		if err != nil {
			log.Fatal(err)
		}
		res := vanmoof.CheckCertificate(cert, vanmoof.Expect{PublicKey: publicKey, Bike: &bikes[i]})
		if !res.Valid {
			log.Fatalf("%s: %v", bike.FrameNumber, res.Errors)
		}
		fmt.Println(bike.FrameNumber, res.AccessLevel(), res.Expires, cert)
	}
}
```

- `Login` never prompts and doesn't use the tool's cache. To log in again later
  without the password, save `s.Tokens()` and continue with `vanmoof.Resume(tokens)`.
  The session renews its tokens when they expire, so save them again after using it.
  Once it can't renew them, its methods return `vanmoof.ErrLoginRequired` (check with
  `errors.Is`).
- `Bikes` returns the account's own bikes, then the ones shared with it. If it can't
  look up the shared ones, it returns the own ones along with an error wrapping
  `vanmoof.ErrSharedBikes`.
- `CheckCertificate` checks the certificate's signature and expiry, and whatever you
  set in `vanmoof.Expect`: the public key, the bike, and the user (`s.UserID()`). `Valid`
  is false if a check failed, and `Errors` says why. No S6 signing key is known yet, so
  for an S6, `SignatureVerified` is false and `Notes` says so.
- `GenerateCertificate` goes the other way: it signs a certificate with a key of your own,
  for a bike whose firmware you've changed to trust that key rather than VanMoof's (see
  [Generate your own certificate](#generate-your-own-certificate-advanced)). A stock bike
  ignores it.
- `s.Invitations()` returns the pending bike sharing invitations, and
  `s.AcceptInvitation(guid)` and `s.DeclineInvitation(guid)` respond to one. Accepting
  returns the bike that's now shared with you.
- A session can be used from several goroutines at once.
- Its requests check the TLS certificates of VanMoof's servers for revocation, as the
  tool does (see [TLS Certificate Revocation](#tls-certificate-revocation)), over a copy of
  `http.DefaultTransport`. A revoked certificate (by OCSP, the CRL or Mozilla's OneCRL)
  makes them fail with an error wrapping `vanmoof.ErrRevoked`, and one left unconfirmed —
  neither OCSP nor the CRL vouches for it, or OneCRL couldn't be fetched — with
  `vanmoof.ErrRevocationUnknown`, unless `vanmoof.SetAllowUnknownRevocation(true)`.
- The tokens, your private key and the certificates let anyone unlock the bike: keep
  them out of logs.

`go doc -all github.com/Knight1/vanmoof-certificates/vanmoof` describes the whole
package. Its `GetCert`, `ShowKeys` and `ProcessCertificate` are the tool's own: they
prompt and print instead of returning their results. The BLE encryption keys of older
bikes (`-show-keys`) aren't available as values yet.
