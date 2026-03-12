import os
import sys
import getpass
import hashlib
import logging
from typing import Tuple, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

logger = logging.getLogger("xtractr.crypto")

class IdentityManager:
    """
    Manages Investigator Identity (Ed25519 Keys).
    Keys are encrypted on disk using a passphrase (BestAvailableEncryption).
    Optionally generates self-signed X.509 certificates for PKI identity binding.
    """

    def __init__(self, key_dir: str):
        self.key_dir = os.path.abspath(key_dir)
        self.private_key_path = os.path.join(self.key_dir, "investigator.pem")
        self.public_key_path = os.path.join(self.key_dir, "investigator.pub")
        self.certificate_path = os.path.join(self.key_dir, "investigator.crt")
        self._private_key = None
        self._public_key = None
        self._passphrase = None

        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir, mode=0o700)

    def load_or_generate_keys(self, passphrase: bytes = None) -> bool:
        """
        Load existing keys or generate new ones if missing.
        If passphrase is None, prompts via getpass.
        Returns True if successful.
        """
        if passphrase is None:
            if os.path.exists(self.private_key_path):
                pp = getpass.getpass("Enter key passphrase: ")
            else:
                pp = getpass.getpass("Create new key passphrase: ")
                pp2 = getpass.getpass("Confirm passphrase: ")
                if pp != pp2:
                    logger.error("Passphrases do not match")
                    return False
            passphrase = pp.encode("utf-8")

        self._passphrase = passphrase

        if os.path.exists(self.private_key_path):
            return self._load_keys(passphrase)
        return self._generate_keys(passphrase)

    def _generate_keys(self, passphrase: bytes) -> bool:
        logger.info("Generating new Ed25519 Identity Keys (encrypted)...")
        self._private_key = ed25519.Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

        # Save Private (encrypted with passphrase)
        encryption = serialization.BestAvailableEncryption(passphrase)
        with open(self.private_key_path, "wb") as f:
            f.write(self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ))
        os.chmod(self.private_key_path, 0o600)

        # Save Public
        with open(self.public_key_path, "wb") as f:
            f.write(self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        # Generate self-signed X.509 certificate
        self._generate_self_signed_cert()

        logger.info(f"Keys saved to {self.key_dir} (encrypted)")
        return True

    def _load_keys(self, passphrase: bytes) -> bool:
        try:
            with open(self.private_key_path, "rb") as f:
                pem_data = f.read()

            # Try loading with passphrase first (new encrypted format)
            try:
                self._private_key = serialization.load_pem_private_key(
                    pem_data, password=passphrase
                )
            except (TypeError, ValueError):
                # Fallback: try loading without passphrase (legacy unencrypted keys)
                try:
                    self._private_key = serialization.load_pem_private_key(
                        pem_data, password=None
                    )
                    logger.warning("Loaded UNENCRYPTED legacy key. Re-encrypting with passphrase...")
                    # Re-save with encryption
                    encryption = serialization.BestAvailableEncryption(passphrase)
                    with open(self.private_key_path, "wb") as f:
                        f.write(self._private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=encryption
                        ))
                    logger.info("Legacy key re-encrypted successfully.")
                except Exception:
                    logger.error("Wrong passphrase or corrupted key file.")
                    return False

            self._public_key = self._private_key.public_key()

            # Generate certificate if missing
            if not os.path.exists(self.certificate_path):
                self._generate_self_signed_cert()

            logger.info("Identity Keys Loaded.")
            return True
        except Exception as e:
            logger.error(f"Failed to load keys: {e}")
            return False

    def _generate_self_signed_cert(self):
        """Generate a self-signed X.509 certificate binding the Ed25519 key to investigator identity."""
        try:
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "XtractR Forensic Lab"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Forensic Investigator"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(self._public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.UTC))
                .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365 * 5))
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .sign(self._private_key, algorithm=None)  # Ed25519 doesn't use a separate hash
            )

            with open(self.certificate_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            logger.info(f"X.509 Certificate generated: {self.certificate_path}")
        except Exception as e:
            logger.warning(f"Certificate generation failed (non-fatal): {e}")

    def sign_data(self, data: bytes) -> bytes:
        if not self._private_key:
            raise ValueError("Private key not loaded")
        return self._private_key.sign(data)

    def verify_signature(self, signature: bytes, data: bytes) -> bool:
        if not self._public_key:
             raise ValueError("Public key not loaded")
        try:
            self._public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    def get_public_key_hex(self) -> str:
        if not self._public_key: return "N/A"
        pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.hex()

    def get_public_key_fingerprint(self) -> str:
        """SHA-256 fingerprint of public key DER bytes (hex lowercase)."""
        if not self._public_key:
            return "N/A"
        der = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(der).hexdigest()

    def get_public_key_pem(self) -> bytes:
        """Return the public key in PEM format."""
        if not self._public_key:
            return b""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_certificate_pem(self) -> bytes:
        """Return the X.509 certificate in PEM format."""
        if os.path.exists(self.certificate_path):
            with open(self.certificate_path, "rb") as f:
                return f.read()
        return b""
