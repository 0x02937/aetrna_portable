# What it is

A standalone Node.js tool to decrypt keys or files previously packed/encrypted with Aetrna. It supports both [ECIES](https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption) and MLKEM (Kyber-1024 per [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)) decryption methods. Run this offline or in VM/sandbox if you care about leaking the private keys from memory.

## What it does

- Decrypts files encrypted with ECIES or Kyber1024 (ML-KEM)
- Extracts just the symmetric key or decrypt the full file
- Modes: Interactive or Command-line arguments for automation

## Installation

- You will need Node.js v16 or later

### Setup

1. Clone or download the repository
2. Navigate to the directory containing the script
3. Install dependencies (or just run a bat file):

```bash
npm install
```

## Usage

The tool can be used in two modes:

1. **Interactive mode** - Guides you through the decryption process
2. **Command-line mode** - For scripting and automation

### Interactive Mode

Simply run bat file or the script without arguments:

```bash
node decrypt.js
```

### Command-line Mode

```bash
node decrypt.js --mode <mode> --encryption <type> --priv-key <key> --enc-key <key> [--enc-data <data>] [--output <path>] [--key-output-format <format>]
```

#### Required Arguments:

- `--mode`: Decryption mode (`key` or `file`)
- `--encryption`: Encryption method (`ecies` or `kyber`)
- `--priv-key`: Private key or path to key file
- `--enc-key`: Encrypted symmetric key or path to key file

#### Optional Arguments:

- `--enc-data`: Encrypted file data or path to file (required if mode is `file`)
- `--output`: Output path for decrypted file (for `file` mode)
- `--key-output-format`: Output format for decrypted key (`hex` or `base64`, default: `hex`)

### Examples

#### Decrypt a Key (ECIES)

```bash
node decrypt.js --mode key --encryption ecies --priv-key 0x1234...5678 --enc-key 0xabcd...ef01
```

#### Decrypt a Key (MLKEM)

```bash
node decrypt.js --mode key --encryption mlkem --priv-key /path/to/mlkem_private_key.txt --enc-key /path/to/encrypted_key.bin
```

#### Decrypt a File (ECIES)

```bash
node decrypt.js --mode file --encryption ecies --priv-key 0x1234...5678 --enc-key 0xabcd...ef01 --enc-data /path/to/encrypted_file.bin --output /path/to/output.pdf
```

## Input Formats

### Private Keys

- **ECIES**: 64 hex characters, with or without '0x' prefix
- **MLKEM**: Base64 encoded 3168-byte key

### Encrypted Keys

- **ECIES**: Hex encoded data, with or without '0x' prefix
- **MLKEM**: Hex or Base64 encoded combined key data

### Encrypted File Data

- Base64 encoded data or path to binary file

## Output

- **Key mode**: Outputs the decrypted symmetric key (AES-256) in hex or base64
- **File mode**: Saves the decrypted file to the specified path or to `./decrypted_<filename>`
