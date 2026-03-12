import pytest
import os
from core.crypto import IdentityManager

@pytest.fixture
def key_dir(tmp_path):
    return str(tmp_path / "keys")

def test_key_generation(key_dir):
    im = IdentityManager(key_dir)
    assert im.load_or_generate_keys(b"test_passphrase_123")
    assert os.path.exists(os.path.join(key_dir, "investigator.pem"))
    assert os.path.exists(os.path.join(key_dir, "investigator.pub"))

def test_signing_verification(key_dir):
    im = IdentityManager(key_dir)
    im.load_or_generate_keys(b"test_passphrase_456")
    
    data = b"evidence_data"
    signature = im.sign_data(data)
    
    assert len(signature) == 64 # Ed25519 signatures are 64 bytes
    assert im.verify_signature(signature, data)
    assert not im.verify_signature(signature, b"tampered_data")

def test_loading_existing_keys(key_dir):
    passphrase = b"test_passphrase_789"
    im1 = IdentityManager(key_dir)
    im1.load_or_generate_keys(passphrase)
    sig = im1.sign_data(b"test")
    
    # Reload in new instance
    im2 = IdentityManager(key_dir)
    im2.load_or_generate_keys(passphrase)
    
    # Verify signature from first instance
    assert im2.verify_signature(sig, b"test")
