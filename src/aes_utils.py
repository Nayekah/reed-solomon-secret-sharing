import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class EncryptedPackage:
    nonce: bytes
    ciphertext: bytes
    associated_data: bytes | None = None


def generate_aes256_key() -> bytes: return AESGCM.generate_key(bit_length=256)
def encrypt_aes_gcm(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> EncryptedPackage:
    nonce = os.urandom(12)
    aes_gcm = AESGCM(key)
    ciphertext = aes_gcm.encrypt(nonce, plaintext, associated_data)
    return EncryptedPackage(nonce=nonce, ciphertext=ciphertext, associated_data=associated_data)

def decrypt_aes_gcm(package: EncryptedPackage, key: bytes) -> bytes:
    aes_gcm = AESGCM(key)
    return aes_gcm.decrypt(package.nonce, package.ciphertext, package.associated_data)

def key_bytes_to_int(key: bytes) -> int: return int.from_bytes(key, byteorder="big", signed=False)
def int_to_key_bytes(value: int, key_size_bytes: int = 32) -> bytes: return value.to_bytes(key_size_bytes, byteorder="big", signed=False)