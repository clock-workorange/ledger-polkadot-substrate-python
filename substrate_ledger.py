#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Substrate Ledger Ed25519 Key Derivation

A complete Python implementation of the Ledger Ed25519 key derivation algorithm
used by Substrate/Polkadot. This implementation is based on the original
@polkadot/util-crypto JavaScript library and produces identical results.

This implementation is compatible with:
- Polkadot JS Apps
- Polkadot{.js} Extension
- Ledger Hardware Wallets
- Substrate-based networks (Polkadot, Kusama, and others)

Author: Claude & Contributors
License: Apache-2.0
"""

import hashlib
import hmac
import binascii
import argparse
import base58
import sys
from typing import List, Dict, Any, Tuple, Optional, Union

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Constants
HARDENED = 0x80000000  # Hardened index offset (2^31)
ED25519_CRYPTO = b'ed25519 seed'  # Key used in HMAC operations

# Network registry of common Substrate networks
# Format: {name: (slip44, ss58prefix, display_name)}
SUBSTRATE_NETWORKS = {
    "polkadot": (354, 0, "Polkadot"),
    "kusama": (434, 2, "Kusama"),
    "westend": (434, 42, "Westend"),
    "rococo": (434, 42, "Rococo"),
    "substrate": (354, 42, "Substrate"),
    "acala": (354, 10, "Acala"),
    "karura": (434, 8, "Karura"),
    "astar": (354, 5, "Astar"),
    "shiden": (434, 5, "Shiden"),
    "moonbeam": (354, 1284, "Moonbeam"),
    "moonriver": (434, 1285, "Moonriver"),
    "centrifuge": (354, 36, "Centrifuge"),
}

#-------------------------------------------------------------------------
# Utility Functions
#-------------------------------------------------------------------------

def bytes_to_hex(data: bytes) -> str:
    """
    Convert bytes to a hexadecimal string.
    
    Args:
        data: Bytes to convert
        
    Returns:
        Hexadecimal string representation
    """
    return binascii.hexlify(data).decode('utf-8')

def hex_to_bytes(hex_string: str) -> bytes:
    """
    Convert a hexadecimal string to bytes.
    
    Args:
        hex_string: Hexadecimal string, with or without '0x' prefix
        
    Returns:
        Corresponding bytes
    """
    if hex_string.startswith('0x'):
        hex_string = hex_string[2:]
    return binascii.unhexlify(hex_string)

def normalize_mnemonic(mnemonic: str) -> str:
    """
    Normalize a mnemonic phrase by removing extra spaces.
    
    Args:
        mnemonic: The mnemonic phrase to normalize
        
    Returns:
        Normalized mnemonic phrase with single spaces
    """
    return " ".join(mnemonic.split())

def hmac_sha_as_bytes(key: bytes, data: bytes, bits: int = 512) -> bytes:
    """
    Emulate the hmacShaAsU8a function from Polkadot JS.
    Compute an HMAC using either SHA-256 or SHA-512.
    
    Args:
        key: The HMAC key
        data: The data to hash
        bits: Hash size (256 or 512 bits)
        
    Returns:
        The resulting HMAC hash
    """
    if bits == 256:
        return hmac.new(key, data, hashlib.sha256).digest()
    elif bits == 512:
        return hmac.new(key, data, hashlib.sha512).digest()
    else:
        raise ValueError(f"Unsupported hash size: {bits}. Use 256 or 512.")

def int_to_bytes_le(value: int, length: int) -> bytes:
    """
    Convert an integer to a little-endian byte array.
    
    Args:
        value: Integer value to convert
        length: Length of the resulting byte array
        
    Returns:
        Bytes in little-endian format
    """
    return value.to_bytes(length, byteorder='little')

def bytes_le_to_int(data: bytes) -> int:
    """
    Convert a little-endian byte array to an integer.
    
    Args:
        data: Bytes in little-endian format
        
    Returns:
        The corresponding integer value
    """
    return int.from_bytes(data, byteorder='little')

#-------------------------------------------------------------------------
# BIP39 and Seed Generation
#-------------------------------------------------------------------------

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Convert a BIP39 mnemonic to a 64-byte seed.
    
    This function implements the BIP39 seed generation algorithm:
    - Takes a mnemonic phrase and optional passphrase
    - Applies PBKDF2-HMAC-SHA512 with 2048 iterations
    - Uses "mnemonic" + passphrase as the salt
    
    Args:
        mnemonic: The BIP39 mnemonic phrase
        passphrase: Optional passphrase for additional security
        
    Returns:
        64-byte BIP39 seed
    """
    # Normalize the mnemonic
    mnemonic = normalize_mnemonic(mnemonic)
    
    # Generate seed using PBKDF2 with HMAC-SHA512
    salt = ("mnemonic" + passphrase).encode("utf-8")
    seed = hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.encode("utf-8"),
        salt,
        iterations=2048
    )
    
    return seed

#-------------------------------------------------------------------------
# Ledger Ed25519 Key Derivation Implementation
#-------------------------------------------------------------------------

def ledger_master(mnemonic: str, password: str = "") -> bytes:
    """
    Generate a master extended key using the Ledger Ed25519 algorithm.
    
    This is an exact implementation of the ledgerMaster function from
    Polkadot JS, which does the following:
    1. Generate a 64-byte BIP39 seed from the mnemonic
    2. Generate a chain code using HMAC-SHA256
    3. Generate a private key through an iterative process using HMAC-SHA512
    4. Apply specific bit operations required by Ed25519
    5. Concatenate the private key and chain code
    
    Args:
        mnemonic: BIP39 mnemonic phrase
        password: Optional password (for 25th word)
        
    Returns:
        96-byte extended key (32-byte private key + 64-byte chain code)
    """
    # Generate BIP39 seed
    seed = mnemonic_to_seed(mnemonic, password)
    
    # Generate chain code
    # chainCode = hmacShaAsU8a(ED25519_CRYPTO, new Uint8Array([1, ...seed]), 256)
    # Add a leading byte of 1 to the seed for chain code generation
    chain_code_data = bytearray([1]) + seed
    chain_code = hmac_sha_as_bytes(ED25519_CRYPTO, chain_code_data, 256)
    
    # Generate private key through iterative process
    # while (!priv || (priv[31] & 0b0010_0000)) {
    #   priv = hmacShaAsU8a(ED25519_CRYPTO, priv || seed, 512)
    # }
    priv = None
    while not priv or (priv[31] & 0b0010_0000):
        priv = hmac_sha_as_bytes(ED25519_CRYPTO, priv if priv else seed, 512)
    
    # Apply Ed25519 specific bit operations
    # priv[0] &= 0b1111_1000
    # priv[31] &= 0b0111_1111
    # priv[31] |= 0b0100_0000
    priv_array = bytearray(priv)
    priv_array[0] &= 0b11111000  # Clear the lowest 3 bits
    priv_array[31] &= 0b01111111  # Clear the highest bit
    priv_array[31] |= 0b01000000  # Set the second highest bit
    
    # Concatenate private key and chain code
    # return u8aConcat(priv, chainCode)
    return bytes(priv_array) + chain_code

def ledger_derive_private(xprv: bytes, index: int) -> bytes:
    """
    Derive a child private key using the Ledger Ed25519 algorithm.
    
    This is an exact implementation of the ledgerDerivePrivate function
    from Polkadot JS, which performs a complex mathematical operation:
    1. Split the extended key into left key (kl), right key (kr), and chain code (cc)
    2. Compute a Z value using HMAC-SHA512
    3. Calculate new kl = kl + (Z_left * 8)
    4. Calculate new kr = kr + Z_right
    5. Calculate new chain code
    6. Concatenate the results
    
    Args:
        xprv: 96-byte extended private key
        index: Derivation index (should be hardened)
        
    Returns:
        96-byte derived extended private key
    """
    # Split extended key into components
    # const kl = xprv.subarray(0, 32)
    # const kr = xprv.subarray(32, 64)
    # const cc = xprv.subarray(64, 96)
    kl = xprv[0:32]
    kr = xprv[32:64]
    cc = xprv[64:96]
    
    # Prepare data for HMAC
    # const data = u8aConcat([0], kl, kr, bnToU8a(index, BN_LE_32_OPTS))
    # Add a leading byte of 0, concatenate kl, kr, and the index in little-endian
    data = bytearray([0]) + kl + kr + int_to_bytes_le(index, 4)
    
    # Compute Z value
    # const z = hmacShaAsU8a(cc, data, 512)
    z = hmac_sha_as_bytes(cc, data, 512)
    
    # Modify first byte of data for next HMAC
    # data[0] = 0x01
    data[0] = 0x01
    
    # Perform mathematical operations as specified in the algorithm
    z_left = z[0:28]  # Only use first 28 bytes of z for kl
    z_right = z[32:64]  # Use bytes 32-64 of z for kr
    
    # Convert to integers for arithmetic
    kl_int = bytes_le_to_int(kl)
    kr_int = bytes_le_to_int(kr)
    z_left_int = bytes_le_to_int(z_left)
    z_right_int = bytes_le_to_int(z_right)
    
    # Calculate new kl: kl + (z_left * 8), truncated to 256 bits
    # kl_new = bnToU8a(u8aToBn(kl, BN_LE_OPTS).iadd(u8aToBn(z.subarray(0, 28), BN_LE_OPTS).imul(BN_EIGHT)), BN_LE_512_OPTS).subarray(0, 32)
    kl_new_int = (kl_int + (z_left_int * 8)) & ((1 << 256) - 1)
    kl_new = int_to_bytes_le(kl_new_int, 32)
    
    # Calculate new kr: kr + z_right, truncated to 256 bits
    # kr_new = bnToU8a(u8aToBn(kr, BN_LE_OPTS).iadd(u8aToBn(z.subarray(32, 64), BN_LE_OPTS)), BN_LE_512_OPTS).subarray(0, 32)
    kr_new_int = (kr_int + z_right_int) & ((1 << 256) - 1)
    kr_new = int_to_bytes_le(kr_new_int, 32)
    
    # Calculate new chain code
    # hmacShaAsU8a(cc, data, 512).subarray(32, 64)
    new_cc = hmac_sha_as_bytes(cc, data, 512)[32:64]
    
    # Concatenate results
    return kl_new + kr_new + new_cc

def hd_ledger(mnemonic: str, path: str) -> Dict[str, bytes]:
    """
    Derive Ed25519 keypair using the Ledger HD derivation algorithm.
    
    This is an exact implementation of the hdLedger function from Polkadot JS,
    which performs the following:
    1. Parse and validate the mnemonic
    2. Extract password if present (25th word)
    3. Validate the derivation path
    4. Generate master seed using ledgerMaster
    5. Derive child keys for each component of the path
    6. Extract the final private key and generate the public key
    
    Args:
        mnemonic: BIP39 mnemonic phrase
        path: Derivation path (m/44'/354'/0'/0'/0')
        
    Returns:
        Dictionary with secretKey and publicKey
    """
    # Normalize mnemonic and split into words
    mnemonic = normalize_mnemonic(mnemonic)
    words = mnemonic.split()
    
    # Validate word count and extract password if present
    if len(words) not in [12, 24, 25]:
        raise ValueError("Expected a mnemonic with 12, 24, or 25 words (including password)")
    
    # Extract password if present (25th word)
    if len(words) == 25:
        mnemonic = " ".join(words[:24])
        password = words[24]
    else:
        mnemonic = " ".join(words)
        password = ""
    
    # Validate derivation path
    if not path.startswith('m/'):
        raise ValueError("Derivation path must start with 'm/'")
    
    # Generate master seed
    seed = ledger_master(mnemonic, password)
    
    # Parse path and derive child keys
    parts = path.split('/')[1:]  # Skip 'm/'
    
    for part in parts:
        # Check for hardened indicator
        if part.endswith("'"):
            part = part[:-1]
            hardened = True
        else:
            hardened = False
        
        # Convert to integer
        try:
            index = int(part)
        except ValueError:
            raise ValueError(f"Invalid path component: {part}")
        
        # Apply hardened if necessary
        if hardened or index < HARDENED:
            index = index | HARDENED
        
        # Derive child key
        seed = ledger_derive_private(seed, index)
    
    # Extract 32-byte private key
    secret_key = seed[:32]
    
    # Generate Ed25519 public key
    public_key = ed25519_publickey(secret_key)
    
    return {
        'secretKey': secret_key,
        'publicKey': public_key
    }

#-------------------------------------------------------------------------
# Ed25519 Public Key Generation
#-------------------------------------------------------------------------

def ed25519_publickey(privatekey: bytes) -> bytes:
    """
    Calculate Ed25519 public key from a private key.
    
    This function uses the cryptography library to properly generate
    an Ed25519 public key according to RFC 8032.
    
    Args:
        privatekey: 32-byte Ed25519 private key
        
    Returns:
        32-byte Ed25519 public key
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError(
            "The 'cryptography' package is required for Ed25519 key generation. "
            "Please install it with: pip install cryptography"
        )
    
    try:
        # Create Ed25519 private key object
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(privatekey)
        
        # Get public key in raw format
        return sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    except Exception as e:
        raise ValueError(f"Error generating Ed25519 public key: {e}")

#-------------------------------------------------------------------------
# Substrate Address Encoding
#-------------------------------------------------------------------------

def ss58_encode(public_key: bytes, prefix: int) -> str:
    """
    Encode a public key as a Substrate SS58 address.
    
    The SS58 format is a modified base58 encoding with:
    1. A network prefix to identify the network
    2. The public key
    3. A checksum calculated using blake2b
    
    Args:
        public_key: 32-byte public key
        prefix: SS58 network prefix
        
    Returns:
        SS58 encoded address
    """
    # Validate public key length
    if len(public_key) != 32:
        raise ValueError(f"Public key must be 32 bytes, got {len(public_key)}")
    
    # Prepare prefix bytes
    if prefix < 64:
        # For prefixes < 64, use a single byte
        prefix_bytes = bytes([prefix])
    else:
        # For larger prefixes, use a special 2-byte encoding
        first = ((prefix & 0x3f) << 2) | 0x40
        second = (prefix >> 6)
        prefix_bytes = bytes([first, second])
    
    # Calculate checksum using blake2b
    # The input is "SS58PRE" + prefix_bytes + public_key
    hasher = hashlib.blake2b(digest_size=64)
    hasher.update(b"SS58PRE")
    hasher.update(prefix_bytes)
    hasher.update(public_key)
    checksum = hasher.digest()
    
    # Encode in base58
    # The input is prefix_bytes + public_key + checksum[:2]
    address_bytes = prefix_bytes + public_key + checksum[:2]
    return base58.b58encode(address_bytes).decode('utf-8')

#-------------------------------------------------------------------------
# Main API Function
#-------------------------------------------------------------------------

def get_substrate_keys(mnemonic: str, path: str = None, account_index: int = 0, 
                     network: str = "polkadot", passphrase: str = "", verbose: bool = False) -> Dict[str, Any]:
    """
    Generate Substrate/Polkadot keys and addresses from a mnemonic.
    
    This function serves as the main API for generating keys and addresses
    compatible with the Substrate/Polkadot ecosystem.
    
    Args:
        mnemonic: BIP39 mnemonic phrase
        path: Custom derivation path (overrides network and account_index)
        account_index: Account index (default 0)
        network: Network name (default "polkadot")
        passphrase: Optional passphrase
        verbose: If True, print additional information
        
    Returns:
        Dictionary with keys and addresses
    """
    # Normalize mnemonic
    mnemonic = normalize_mnemonic(mnemonic)
    
    # Get network parameters
    network = network.lower()
    if network not in SUBSTRATE_NETWORKS:
        networks_str = ", ".join(SUBSTRATE_NETWORKS.keys())
        raise ValueError(f"Unknown network: {network}. Supported networks: {networks_str}")
    
    slip44, ss58_prefix, network_name = SUBSTRATE_NETWORKS[network]
    
    # Determine derivation path
    if path is None:
        # Construct path using network parameters
        path = f"m/44'/{slip44}'/{account_index}'/0'/0'"
    
    if verbose:
        print(f"Network: {network_name}")
        print(f"Derivation path: {path}")
    
    # Derive keys using Ledger algorithm
    pair = hd_ledger(mnemonic, path)
    private_key = pair['secretKey']
    public_key = pair['publicKey']
    
    if verbose:
        print(f"Private key: 0x{bytes_to_hex(private_key)}")
        print(f"Public key: 0x{bytes_to_hex(public_key)}")
    
    # Generate addresses for primary network and Polkadot/Kusama
    network_address = ss58_encode(public_key, ss58_prefix)
    
    # For non-Polkadot/Kusama networks, also generate Polkadot and Kusama addresses
    addresses = {
        f"{network_name}": network_address
    }
    
    # Always include Polkadot and Kusama addresses
    if network != "polkadot":
        addresses["Polkadot"] = ss58_encode(public_key, 0)
    if network != "kusama":
        addresses["Kusama"] = ss58_encode(public_key, 2)
    
    return {
        'ed25519_seed': bytes_to_hex(private_key),
        'private_key': bytes_to_hex(private_key),
        'public_key': bytes_to_hex(public_key),
        'addresses': addresses,
        'path': path
    }

#-------------------------------------------------------------------------
# Command-line Interface
#-------------------------------------------------------------------------

def main():
    """
    Command-line interface for Substrate Ledger Ed25519 key derivation.
    """
    parser = argparse.ArgumentParser(
        description="Substrate/Polkadot Ed25519 Key Generator",
        epilog="Example: substrate_ledger.py 'word1 word2 ... word12' --network kusama --account 0"
    )
    
    # Required arguments
    parser.add_argument("mnemonic", help="BIP39 mnemonic phrase (12, 24, or 25 words)")
    
    # Optional arguments
    parser.add_argument("--account", type=int, default=0, help="Account index (default: 0)")
    parser.add_argument("--network", default="polkadot", help=f"Network name (default: polkadot, options: {', '.join(SUBSTRATE_NETWORKS.keys())})")
    parser.add_argument("--path", help="Custom derivation path (overrides --network and --account)")
    parser.add_argument("--passphrase", default="", help="Optional passphrase (default: none)")
    parser.add_argument("--verbose", action="store_true", help="Show detailed information")
    parser.add_argument("--version", action="version", version="Substrate Ledger Ed25519 v1.0.0")
    
    args = parser.parse_args()
    
    try:
        # Check for cryptography package
        if not CRYPTOGRAPHY_AVAILABLE:
            print("Error: The 'cryptography' package is required.")
            print("Please install it with: pip install cryptography")
            return 1
        
        # Derive keys and addresses
        result = get_substrate_keys(
            args.mnemonic, 
            args.path, 
            args.account, 
            args.network, 
            args.passphrase,
            args.verbose
        )
        
        # Print results in a format similar to the original JavaScript tool
        print(f"\n\t ed25519 seed\t 0x{result['ed25519_seed']}")
        print()
        
        # Print addresses
        for network, address in result['addresses'].items():
            print(f"\taddress ({network})\t {address}")
        
        # Print additional details
        print("\nAdditional details:")
        print(f"Derivation path: {result['path']}")
        print(f"Public key: 0x{result['public_key']}")
        
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
