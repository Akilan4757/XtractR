import hashlib
import os

def calculate_file_hash(filepath):
    """Calculate SHA256 hash of a file using chunked reading."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""): # 64KB chunks
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except OSError:
        return None

def calculate_string_hash(s):
    """Calculate SHA256 hash of a string."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def calculate_event_hash(payload, prev_hash):
    """Calculate the hash of an event payload chained with the previous hash."""
    combined = f"{payload}|{prev_hash}"
    return calculate_string_hash(combined)

def build_merkle_root(files_map):
    """
    Build a deterministic Merkle tree root from a dictionary of relative_path -> sha256.
    Leaf Nodes = sha256(relative_path + ":" + file_hash)
    """
    if not files_map:
        return "EMPTY_TREE"

    # Sort keys for determinism
    sorted_paths = sorted(files_map.keys())
    leaves = []
    
    for path in sorted_paths:
        file_hash = files_map[path]
        leaf_content = f"{path}:{file_hash}"
        leaves.append(calculate_string_hash(leaf_content))
    
    current_level = leaves
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = calculate_string_hash(left + right)
            next_level.append(combined)
        current_level = next_level
        
    return current_level[0]
