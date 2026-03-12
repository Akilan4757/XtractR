"""
XtractR RFC 3161 Time Stamp Authority Client

Provides external time anchoring to prevent OS clock manipulation.
Sends a SHA-256 digest to a trusted TSA and receives a signed timestamp token.
"""
import hashlib
import logging
import os
from typing import Optional

logger = logging.getLogger("xtractr.tsa")

# Default public TSA endpoint
DEFAULT_TSA_URL = "https://freetsa.org/tsr"


class TSAClient:
    """
    RFC 3161 Time Stamp Authority client.
    Anchors cryptographic seals to verifiable external time.
    """

    def __init__(self, tsa_url: str = DEFAULT_TSA_URL):
        self.tsa_url = tsa_url

    def request_timestamp(self, data: bytes) -> Optional[bytes]:
        """
        Send a SHA-256 digest to the TSA and return the signed timestamp token.
        Returns None if the TSA is unreachable (degraded mode).
        """
        try:
            import urllib.request
            import struct

            # Compute SHA-256 digest
            digest = hashlib.sha256(data).digest()

            # Build a minimal RFC 3161 TimeStampReq (DER-encoded ASN.1)
            # This is a simplified construction for the most common TSA format
            tsq = self._build_timestamp_request(digest)

            req = urllib.request.Request(
                self.tsa_url,
                data=tsq,
                headers={
                    "Content-Type": "application/timestamp-query",
                    "Accept": "application/timestamp-reply",
                },
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    token = resp.read()
                    logger.info(f"TSA timestamp received ({len(token)} bytes)")
                    return token
                else:
                    logger.warning(f"TSA returned HTTP {resp.status}")
                    return None

        except Exception as e:
            logger.warning(f"TSA_UNREACHABLE: {e} — continuing in degraded mode (no external time anchor)")
            return None

    def _build_timestamp_request(self, digest: bytes) -> bytes:
        """
        Build a minimal RFC 3161 TimeStampReq for SHA-256.
        DER-encoded ASN.1 structure.
        """
        # OID for SHA-256: 2.16.840.1.101.3.4.2.1
        sha256_oid = bytes([
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
        ])

        # AlgorithmIdentifier SEQUENCE
        alg_id = bytes([0x30, len(sha256_oid) + 2]) + sha256_oid + bytes([0x05, 0x00])

        # MessageImprint SEQUENCE
        digest_octet = bytes([0x04, len(digest)]) + digest
        msg_imprint = bytes([0x30, len(alg_id) + len(digest_octet)]) + alg_id + digest_octet

        # Version INTEGER 1
        version = bytes([0x02, 0x01, 0x01])

        # CertReq BOOLEAN TRUE
        cert_req = bytes([0x01, 0x01, 0xFF])

        # TimeStampReq SEQUENCE
        body = version + msg_imprint + cert_req
        tsq = bytes([0x30, len(body)]) + body

        return tsq

    @staticmethod
    def save_token(token: bytes, path: str):
        """Save the TSA token to a .tsr file."""
        with open(path, "wb") as f:
            f.write(token)
        logger.info(f"TSA token saved: {path}")

    @staticmethod
    def load_token(path: str) -> Optional[bytes]:
        """Load a TSA token from a .tsr file."""
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        return None
