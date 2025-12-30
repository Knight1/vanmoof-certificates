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

\`\`\`bash
go build
\`\`\`

## Usage

### Interactive Mode

Run without any flags to be prompted for credentials:

\`\`\`bash
./vanmoof-certificates
\`\`\`

This will:
1. Prompt for your VanMoof email
2. Prompt for your password (hidden input)
3. Fetch all SA5 or later bikes and generate certificates

### Command-Line Mode

Provide credentials via flags:

\`\`\`bash
./vanmoof-certificates -email user@example.com -password yourpassword
\`\`\`

### Select Specific Bikes

**Process all bikes (default):**
\`\`\`bash
./vanmoof-certificates -email user@example.com -password yourpassword -bikes all
\`\`\`

**Process specific bikes by ID:**
\`\`\`bash
./vanmoof-certificates -email user@example.com -password yourpassword -bikes 176393,138884
\`\`\`

**Interactive bike selection:**
\`\`\`bash
./vanmoof-certificates -email user@example.com -password yourpassword -bikes ask
\`\`\`

This will display your SA5 bikes and prompt you to select which ones to process.

### Debug Mode

Enable debug output to see detailed API requests and responses:

\`\`\`bash
./vanmoof-certificates -email user@example.com -debug
\`\`\`

### Parse Existing Certificate

Parse a certificate without fetching from API:

\`\`\`bash
./vanmoof-certificates -cert "BASE64_CERTIFICATE_STRING"
\`\`\`

With optional public key verification:

\`\`\`bash
./vanmoof-certificates -cert "BASE64_CERT" -pubkey "BASE64_PUBKEY" -bikeid "BIKE_ID"
\`\`\`

## Example Output

\`\`\`
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
\`\`\`

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| \`-email\` | VanMoof email address | Prompt if not provided |
| \`-password\` | VanMoof password | Prompt if not provided |
| \`-bikes\` | Bikes to process: 'all', IDs (comma-separated), or 'ask' | \`all\` |
| \`-debug\` | Enable debug output | \`false\` |
| \`-cert\` | Base64 encoded certificate to parse | - |
| \`-pubkey\` | Base64 encoded public key (optional) | - |
| \`-bikeid\` | Bike ID for verification (optional) | - |
| \`-version\` | Print version information | - |

## Requirements

- Go 1.24 or later
- VanMoof account with registered SA5 or later bike(s)
