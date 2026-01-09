# vanmoof-certificates

## Installation

```console
go build -ldflags "-w -d"
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
./vanmoof-certificates -email user@example.com -password yourpassword -bikes 42,1337
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