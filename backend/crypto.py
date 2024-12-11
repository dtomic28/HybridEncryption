import os
import rsa
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def generate_rsa_keys():
    """Generates RSA public/private key pair."""
    return rsa.newkeys(2048)


def generate_symmetric_key():
    """Generates a random symmetric key."""
    return os.urandom(32)


def generate_iv():
    """Generates a random initialization vector (IV)."""
    return os.urandom(16)


def calculate_diffie_hellman_shared_secret(private_key, peer_public_key):
    """
    Calculates a Diffie-Hellman shared secret.
    This function assumes you're using a Diffie-Hellman library or custom implementation.
    """
    # Example using an RSA key pair and not Diffie-Hellman directly.
    # In a real Diffie-Hellman setup, you'd perform actual DH computations here.
    return private_key * peer_public_key  # This is just a placeholder.


def dh_calculate_shared_key(private_key, peer_public_key, iv):
    """
    This function assumes you're using RSA key exchange to get the shared key.
    We don't multiply the keys, but instead use RSA to exchange a symmetric key and 
    then use that to derive the shared key using HKDF.
    """
    # For RSA, you can use the peer's public key to encrypt/decrypt a symmetric key
    # But we do not multiply the private and public keys. Instead, we use RSA for secure key exchange.

    # In this setup, we're assuming the symmetric key is already securely exchanged.
    # Let's combine the symmetric key and IV to derive the shared key using HKDF
    # Assuming symmetric key and IV for simplicity
    combined_key = private_key + peer_public_key + iv
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake'
    ).derive(combined_key)

    return derived_key


def calculate_checksum(file_path):
    """Calculates a checksum (SHA256 hash) of a file."""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None


# Example usage:
if __name__ == "__main__":
    # Generate RSA keys
    public_key, private_key = generate_rsa_keys()
    print(f"Generated RSA keys. Public key: {
          public_key}, Private key: {private_key}")

    # Generate symmetric key and IV
    symmetric_key = generate_symmetric_key()
    iv = generate_iv()
    print(f"Generated symmetric key: {symmetric_key.hex()} and IV: {iv.hex()}")

    # Example Diffie-Hellman shared key calculation
    peer_public_key = os.urandom(32)  # Simulating peer's public key
    shared_key = dh_calculate_shared_key(private_key, peer_public_key, iv)
    print(f"Derived shared key: {shared_key.hex()}")

    # Calculate checksum of a file
    file_path = "example_file.txt"  # Specify the path to your file here
    checksum = calculate_checksum(file_path)
    if checksum:
        print(f"Checksum of the file: {checksum}")
