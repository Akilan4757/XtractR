"""
Key Encryption Test Suite

Verifies:
  1. Keys are encrypted on disk (not readable without passphrase)  
  2. Loading with wrong passphrase fails
  3. Signing/verification works with correct passphrase
  4. Legacy unencrypted keys are auto-migrated
"""
import os
import sys
import shutil
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto import IdentityManager
from cryptography.hazmat.primitives import serialization


@pytest.fixture
def key_dir(tmp_path):
    return str(tmp_path / "keys")


class TestKeyEncryption:
    def test_keys_generated_encrypted(self, key_dir):
        """Keys should be encrypted on disk."""
        im = IdentityManager(key_dir)
        assert im.load_or_generate_keys(b"strong_passphrase_42")

        # Verify the PEM file is encrypted (contains ENCRYPTED in header)
        with open(os.path.join(key_dir, "investigator.pem"), "rb") as f:
            pem_data = f.read()
        assert b"ENCRYPTED" in pem_data, "Private key should be encrypted on disk"

    def test_wrong_passphrase_fails(self, key_dir):
        """Loading with wrong passphrase should fail."""
        im1 = IdentityManager(key_dir)
        im1.load_or_generate_keys(b"correct_password")

        im2 = IdentityManager(key_dir)
        result = im2.load_or_generate_keys(b"wrong_password_totally")
        assert not result, "Loading with wrong passphrase should return False"

    def test_correct_passphrase_works(self, key_dir):
        """Signing and verification should work with correct passphrase."""
        im = IdentityManager(key_dir)
        im.load_or_generate_keys(b"my_passphrase_123")

        data = b"forensic evidence hash data"
        sig = im.sign_data(data)

        assert len(sig) == 64, "Ed25519 signatures are 64 bytes"
        assert im.verify_signature(sig, data)
        assert not im.verify_signature(sig, b"tampered")

    def test_reloaded_keys_verify(self, key_dir):
        """Keys reloaded from disk should verify signatures from original."""
        passphrase = b"consistent_passphrase"

        im1 = IdentityManager(key_dir)
        im1.load_or_generate_keys(passphrase)
        sig = im1.sign_data(b"evidence")

        im2 = IdentityManager(key_dir)
        im2.load_or_generate_keys(passphrase)
        assert im2.verify_signature(sig, b"evidence")

    def test_certificate_generated(self, key_dir):
        """X.509 certificate should be generated alongside keys."""
        im = IdentityManager(key_dir)
        im.load_or_generate_keys(b"cert_test_passphrase")

        cert_path = os.path.join(key_dir, "investigator.crt")
        assert os.path.exists(cert_path), "Certificate should be generated"

        cert_pem = im.get_certificate_pem()
        assert b"CERTIFICATE" in cert_pem

    def test_public_key_fingerprint(self, key_dir):
        """Public key fingerprint should be a valid hex string."""
        im = IdentityManager(key_dir)
        im.load_or_generate_keys(b"fingerprint_test")

        fp = im.get_public_key_fingerprint()
        assert len(fp) == 64, "SHA-256 fingerprint should be 64 hex chars"
        assert all(c in "0123456789abcdef" for c in fp)

    def test_legacy_unencrypted_key_migration(self, key_dir):
        """Legacy unencrypted keys should be auto-migrated to encrypted."""
        # First generate an UNENCRYPTED key manually
        os.makedirs(key_dir, exist_ok=True)
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        priv_path = os.path.join(key_dir, "investigator.pem")
        pub_path = os.path.join(key_dir, "investigator.pub")

        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(pub_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        # Now load with IdentityManager — should auto-migrate
        im = IdentityManager(key_dir)
        result = im.load_or_generate_keys(b"migration_passphrase")
        assert result, "Legacy key migration should succeed"

        # Verify the key is now encrypted
        with open(priv_path, "rb") as f:
            new_pem = f.read()
        assert b"ENCRYPTED" in new_pem, "Key should be re-encrypted after migration"
