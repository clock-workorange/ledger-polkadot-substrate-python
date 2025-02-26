# ledger-polkadot-substrate-python
A Python implementation of the Ledger Ed25519 key derivation algorithm used by Substrate/Polkadot. This library generates identical keys and addresses as Polkadot.js and Ledger hardware wallets.

## Features

- Implements the exact Ledger Ed25519 derivation algorithm used by Substrate/Polkadot
- Generates compatible Ed25519 keypairs from BIP39 mnemonic phrases
- Creates valid SS58 addresses for all Substrate-based networks
- Supports multiple networks (Polkadot, Kusama, and other Substrate chains)
- Provides both a command-line interface and a Python API

## Installation

```bash
# Clone the repository
git clone https://github.com/clock-workorange/ledger-polkadot-substrate-python.git
cd ledger-polkadot-substrate-python

# Install dependencies
pip install cryptography base58
```

## Usage

### Command-line Interface

```bash
# Basic usage with default network (Polkadot)
python substrate_ledger.py "word1 word2 ... word12"

# Specify a different network (e.g., Kusama)
python substrate_ledger.py "word1 word2 ... word12" --network kusama

# Use a different account index
python substrate_ledger.py "word1 word2 ... word12" --account 1

# Specify a custom derivation path
python substrate_ledger.py "word1 word2 ... word12" --path "m/44'/354'/2'/0'/0'"

# Show verbose output
python substrate_ledger.py "word1 word2 ... word12" --verbose
```

### Python API

```python
from substrate_ledger import get_substrate_keys

# Generate keys for Polkadot
result = get_substrate_keys("word1 word2 ... word12")

# Generate keys for Kusama
result = get_substrate_keys("word1 word2 ... word12", network="kusama")

# Use a specific account index
result = get_substrate_keys("word1 word2 ... word12", account_index=1)

# Use a custom derivation path
result = get_substrate_keys("word1 word2 ... word12", path="m/44'/354'/2'/0'/0'")

# Access the generated keys and addresses
private_key = result['private_key']
public_key = result['public_key']
polkadot_address = result['addresses']['Polkadot']
kusama_address = result['addresses']['Kusama']
```

## Supported Networks

The library supports the following Substrate-based networks:

- Polkadot (DOT) - SLIP44: 354, SS58 Prefix: 0
- Kusama (KSM) - SLIP44: 434, SS58 Prefix: 2
- Westend - SLIP44: 434, SS58 Prefix: 42
- Rococo - SLIP44: 434, SS58 Prefix: 42
- Substrate - SLIP44: 354, SS58 Prefix: 42
- Acala - SLIP44: 354, SS58 Prefix: 10
- Karura - SLIP44: 434, SS58 Prefix: 8
- Astar - SLIP44: 354, SS58 Prefix: 5
- Shiden - SLIP44: 434, SS58 Prefix: 5
- Moonbeam - SLIP44: 354, SS58 Prefix: 1284
- Moonriver - SLIP44: 434, SS58 Prefix: 1285
- Centrifuge - SLIP44: 354, SS58 Prefix: 36

You can easily add support for additional networks by updating the `SUBSTRATE_NETWORKS` dictionary.

## Examples

### Example 1: Generate Polkadot keys from a mnemonic

```bash
python substrate_ledger.py "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Output:
#      ed25519 seed    0x98cb4e14e0e08ea876f88d728545ea7572dc07dbbe69f1731c418fb827e69d41
#
#    address (Polkadot)        15F8gp3or2mLW8yiJAZ9C3ZFpvEA8SPJDq4RXVpVjcXtdxJq
#    address (Kusama)          GpTCo8cccWnpFne7EKBwr677tWkEoeLbiAgks76fKisCUWP
```

### Example 2: Generate Kusama keys with a specific account index

```bash
python substrate_ledger.py "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --network kusama --account 5

# Output:
#      ed25519 seed    0x4838df591f51189a629584bab74f5404fc25a9e1a07948c939e6b19a2de69d41
#
#    address (Kusama)          J1DSieL2MVsxxFVsLjJhLrFmBpCzTjzDdWXoP2cUE6t8hBG
#    address (Polkadot)        16RtvjZXFmkReqSa4GyFwYKQUDXct6UwqkQGa1k1YWuuaBfA
```

## Technical Details

This library implements the Ledger Ed25519 derivation algorithm, which differs from the standard SLIP-0010 algorithm. The key differences include:

1. **Master Key Generation**: Uses an iterative process with specific bit manipulations
2. **Child Key Derivation**: Employs a complex mathematical algorithm with little-endian encoding
3. **Ed25519 Constraints**: Applies the necessary constraints required by the Ed25519 curve

The implementation is based on the original JavaScript code from the Polkadot.js library, specifically the `hdLedger`, `ledgerMaster`, and `ledgerDerivePrivate` functions.

## License

Apache-2.0
