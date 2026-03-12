from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import os

def generate_keys(key_dir):
    """Generate Ed25519 key pair and save to disk."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    os.makedirs(key_dir, exist_ok=True)
    
    with open(os.path.join(key_dir, "investigator_priv.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    with open(os.path.join(key_dir, "investigator_pub.pem"), "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key, public_key

def load_keys(key_dir):
    """Load keys from disk."""
    priv_path = os.path.join(key_dir, "investigator_priv.pem")
    pub_path = os.path.join(key_dir, "investigator_pub.pem")
    
    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        return generate_keys(key_dir)
        
    with open(priv_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
        
    with open(pub_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
        
    return private_key, public_key

def sign_data(private_key, data):
    """Sign bytes data using Ed25519."""
    return private_key.sign(data)

def verify_signature(public_key, signature, data):
    """Verify Ed25519 signature."""
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False
