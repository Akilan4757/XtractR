import pytest
import os
from orchestrator.signing import generate_keys, load_keys, sign_data, verify_signature

def test_key_gen(tmp_path):
    key_dir = tmp_path / "keys"
    priv, pub = generate_keys(str(key_dir))
    
    assert os.path.exists(key_dir / "investigator_priv.pem")
    assert os.path.exists(key_dir / "investigator_pub.pem")

def test_sign_verify(tmp_path):
    key_dir = tmp_path / "keys"
    priv, pub = generate_keys(str(key_dir))
    
    data = b"evidence_data"
    sig = sign_data(priv, data)
    
    assert verify_signature(pub, sig, data) == True
    assert verify_signature(pub, sig, b"tampered") == False

def test_load_keys(tmp_path):
    key_dir = tmp_path / "keys"
    generate_keys(str(key_dir))
    
    priv, pub = load_keys(str(key_dir))
    assert priv
    assert pub
