import os
import json
import base64
from typing import Tuple, List

# RSA implementation ---------------------------------------------------------

import random
from sympy import randprime, mod_inverse


def generate_rsa_keypair(bit_length: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """Generate an RSA key pair."""
    # Choose two random primes of half the target bit length.
    p = randprime(2 ** (bit_length // 2 - 1), 2 ** (bit_length // 2))
    q = randprime(2 ** (bit_length // 2 - 1), 2 ** (bit_length // 2))
    n = p * q
    phi = (p - 1) * (q - 1)
    # Use the common public exponent 65537.
    e = 65537
    # Compute the modular inverse of e modulo phi.
    d = mod_inverse(e, phi)
    return (e, n), (d, n)


def rsa_encrypt(data: bytes, public_key: Tuple[int, int]) -> bytes:
    """Encrypt a byte string using RSA."""
    e, n = public_key
    m = int.from_bytes(data, byteorder="big")
    if m >= n:
        raise ValueError("Data too large to encrypt with this modulus")
    c = pow(m, e, n)
    # Pad the ciphertext to the modulus size in bytes.
    cipher_length = (n.bit_length() + 7) // 8
    return c.to_bytes(cipher_length, byteorder="big")


def rsa_decrypt(ciphertext: bytes, private_key: Tuple[int, int]) -> bytes:
    """Decrypt a byte string using RSA. """
    d, n = private_key
    c = int.from_bytes(ciphertext, byteorder="big")
    m = pow(c, d, n)
    # The original plaintext may have had leading zeros; recover the
    # original byte length by stripping leading zeros from the numeric
    # representation only if necessary.
    # Convert m to the minimal number of bytes necessary to represent it.
    byte_length = max(1, (m.bit_length() + 7) // 8)
    return m.to_bytes(byte_length, byteorder="big")


# AES implementation ---------------------------------------------------------

from functools import lru_cache


def _gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) with the AES irreducible polynomial."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B  # x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return result


@lru_cache(maxsize=256)
def _gf_inv(a: int) -> int:
    """Compute the multiplicative inverse of a byte in GF(2^8)."""
    if a == 0:
        return 0
    # Extended Euclidean algorithm in GF(2)
    r0, r1 = 0x11B, a  # The irreducible polynomial and the element
    t0, t1 = 0, 1
    while r1 != 1:
        # Polynomial division: compute degree difference and subtract
        deg_r0 = r0.bit_length() - 1
        deg_r1 = r1.bit_length() - 1
        shift = deg_r0 - deg_r1
        if shift < 0:
            r0, r1 = r1, r0
            t0, t1 = t1, t0
            shift = -shift
        r0 ^= r1 << shift
        t0 ^= t1 << shift
    return t1 & 0xFF


# -----------------------------------------------------------------------------
# Precompute S‑box and inverse S‑box tables

def _compute_sbox_tables() -> Tuple[List[int], List[int]]:
    """Compute AES S‑box and its inverse."""

    sbox = [0] * 256
    inv_sbox = [0] * 256
    for i in range(256):
        inv = _gf_inv(i)
        # Affine transform: y = inv ^ (inv<<1) ^ (inv<<2) ^ (inv<<3) ^ (inv<<4) ^ 0x63
        y = inv
        for shift in (1, 2, 3, 4):
            y ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        y ^= 0x63
        sbox[i] = y & 0xFF
    # Build inverse mapping
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return sbox, inv_sbox


# Initialize S‑box tables
_SBOX, _INV_SBOX = _compute_sbox_tables()


def _sub_byte(b: int) -> int:
    """Lookup S‑box substitution for a byte."""
    return _SBOX[b]


def _sub_bytes(state: List[int]) -> None:
    """Perform the SubBytes step on the AES state in place."""
    for i in range(16):
        state[i] = _sub_byte(state[i])


def _inv_sub_bytes(state: List[int]) -> None:
    """Perform the inverse SubBytes step on the AES state in place."""
    for i in range(16):
        state[i] = _INV_SBOX[state[i]]


def _shift_rows(state: List[int]) -> None:
    """Perform the ShiftRows step on the AES state in place."""
    # Row 0: no shift
    # Row 1: shift left by 1
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    # Row 2: shift left by 2
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    # Row 3: shift left by 3
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _inv_shift_rows(state: List[int]) -> None:
    """Perform the inverse ShiftRows step on the AES state in place."""
    # Row 1: shift right by 1
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    # Row 2: shift right by 2
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    # Row 3: shift right by 3
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]


def _mix_columns(state: List[int]) -> None:
    """Perform the MixColumns step on the AES state in place."""
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = state[i:i+4]
        # The MixColumns transformation multiplies the state column by a
        # fixed matrix.  This can be computed using the GF(2^8) helper
        # function.
        state[i]   = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        state[i+1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        state[i+2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        state[i+3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)


def _inv_mix_columns(state: List[int]) -> None:
    """Perform the inverse MixColumns step on the AES state in place."""
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = state[i:i+4]
        state[i]   = _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
        state[i+1] = _gf_mul(a0, 9)  ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
        state[i+2] = _gf_mul(a0, 13) ^ _gf_mul(a1, 9)  ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
        state[i+3] = _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9)  ^ _gf_mul(a3, 14)


def _bytes_to_state(block: bytes) -> List[int]:
    """Convert a 16‑byte block into a list representing the AES state."""
    return list(block)


def _state_to_bytes(state: List[int]) -> bytes:
    """Convert the AES state list back into a 16‑byte bytes object."""
    return bytes(state)


def _expand_key(key: bytes) -> List[List[int]]:
    """Generate round keys for AES‑128."""
    assert len(key) == 16
    # Number of 32‑bit words comprising the key and the expanded key.
    Nk = 4  # for 128‑bit key
    Nb = 4  # block size in words
    Nr = 10  # number of rounds
    # Convert the key into a list of 4‑byte words.
    key_words = [list(key[i:i+4]) for i in range(0, 16, 4)]
    # Rcon values: exponentiation of 2 in GF(2^8)
    rcon = [0] * (Nr + 1)
    rcon[1] = 1
    for i in range(2, Nr + 1):
        rcon[i] = _gf_mul(rcon[i-1], 2)
    # Expand key
    w = key_words.copy()
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i-1].copy()
        if i % Nk == 0:
            # Rotate
            temp = temp[1:] + temp[:1]
            # Substitute bytes
            temp = [_sub_byte(b) for b in temp]
            # XOR with Rcon
            temp[0] ^= rcon[i // Nk]
        # XOR with word Nk positions earlier
        w.append([w[i-Nk][j] ^ temp[j] for j in range(4)])
    # Group into round keys (16 bytes each)
    round_keys = []
    for r in range(Nr + 1):
        key_bytes = []
        for i in range(4):
            key_bytes.extend(w[r * Nb + i])
        round_keys.append(key_bytes)
    return round_keys


def _add_round_key(state: List[int], round_key: List[int]) -> None:
    """XOR the state with the round key."""
    for i in range(16):
        state[i] ^= round_key[i]


def _encrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    """Encrypt a single 16‑byte block using AES‑128."""
    state = _bytes_to_state(block)
    # Initial AddRoundKey
    _add_round_key(state, round_keys[0])
    # 9 main rounds
    for r in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])
    # Final round (no MixColumns)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    return _state_to_bytes(state)


def _decrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    """Decrypt a single 16‑byte block using AES‑128."""
    state = _bytes_to_state(block)
    Nr = 10
    # Initial AddRoundKey with the last round key
    _add_round_key(state, round_keys[Nr])
    # Main rounds in reverse order: Nr-1 down to 1
    for r in range(Nr - 1, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[r])
        _inv_mix_columns(state)
    # Final round (r = 0): perform inverse ShiftRows, inverse SubBytes and AddRoundKey
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return _state_to_bytes(state)


def _pkcs7_pad(data: bytes) -> bytes:
    """Apply PKCS#7 padding to a byte string to a multiple of 16 bytes."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding from a byte string."""
    if not data or len(data) % 16 != 0:
        raise ValueError("Invalid padding")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt arbitrary length plaintext using AES‑128 in CBC mode."""
    if len(key) != 16:
        raise ValueError("AES key must be 16 bytes (128 bits)")
    round_keys = _expand_key(key)
    padded = _pkcs7_pad(plaintext)
    # Generate random IV
    iv = os.urandom(16)
    prev = iv
    ciphertext = b""
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        # XOR with previous ciphertext (CBC chaining)
        block_to_encrypt = bytes([b ^ p for b, p in zip(block, prev)])
        enc_block = _encrypt_block(block_to_encrypt, round_keys)
        ciphertext += enc_block
        prev = enc_block
    return iv + ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt ciphertext produced by `aes_encrypt`."""
    if len(key) != 16:
        raise ValueError("AES key must be 16 bytes (128 bits)")
    if len(ciphertext) < 32 or len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext too short or not properly padded")
    round_keys = _expand_key(key)
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    prev = iv
    plaintext_padded = b""
    for i in range(0, len(ct), 16):
        block = ct[i:i+16]
        dec_block = _decrypt_block(block, round_keys)
        # XOR with previous ciphertext block (CBC chaining)
        plain_block = bytes([b ^ p for b, p in zip(dec_block, prev)])
        plaintext_padded += plain_block
        prev = block
    return _pkcs7_unpad(plaintext_padded)


# Helper functions for encoding/decoding keys --------------------------------

def serialize_public_key(public_key: Tuple[int, int]) -> str:
    """Serialize an RSA public key into a base64‑encoded JSON string."""
    e, n = public_key
    data = {
        "e": str(e),
        "n": str(n),
    }
    return base64.b64encode(json.dumps(data).encode()).decode()


def deserialize_public_key(encoded: str) -> Tuple[int, int]:
    """Deserialize an RSA public key from a base64‑encoded JSON string."""
    data = json.loads(base64.b64decode(encoded.encode()).decode())
    return int(data["e"]), int(data["n"])


def serialize_private_key(private_key: Tuple[int, int]) -> str:
    """Serialize an RSA private key into a base64‑encoded JSON string."""
    d, n = private_key
    data = {
        "d": str(d),
        "n": str(n),
    }
    return base64.b64encode(json.dumps(data).encode()).decode()


def deserialize_private_key(encoded: str) -> Tuple[int, int]:
    """Deserialize an RSA private key from a base64‑encoded JSON string."""
    data = json.loads(base64.b64decode(encoded.encode()).decode())
    return int(data["d"]), int(data["n"])


def generate_aes_key() -> bytes:
    """Generate a 16‑byte AES session key."""
    return os.urandom(16)


def encrypt_session_key(session_key: bytes, recipient_public_key: Tuple[int, int]) -> str:
    """Encrypt an AES session key for a recipient."""
    ct = rsa_encrypt(session_key, recipient_public_key)
    return base64.b64encode(ct).decode()


def decrypt_session_key(encoded_ciphertext: str, private_key: Tuple[int, int]) -> bytes:
    """Decrypt an AES session key using the private RSA key."""
    ct = base64.b64decode(encoded_ciphertext.encode())
    return rsa_decrypt(ct, private_key)


def encrypt_message(plaintext: str, session_key: bytes) -> str:
    """Encrypt a plaintext message using AES‑CBC."""
    pt_bytes = plaintext.encode()
    ct = aes_encrypt(pt_bytes, session_key)
    return base64.b64encode(ct).decode()


def decrypt_message(encoded_ciphertext: str, session_key: bytes) -> str:
    """Decrypt a base64‑encoded ciphertext using AES‑CBC."""
    ct = base64.b64decode(encoded_ciphertext.encode())
    pt_bytes = aes_decrypt(ct, session_key)
    return pt_bytes.decode()
