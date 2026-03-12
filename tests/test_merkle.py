import pytest
from orchestrator.hashing import build_merkle_root, calculate_string_hash

def test_merkle_empty():
    assert build_merkle_root({}) == "EMPTY_TREE"

def test_merkle_single():
    files = {"file1.txt": "hash1"}
    # Leaf: hash("file1.txt:hash1")
    expected = calculate_string_hash("file1.txt:hash1")
    assert build_merkle_root(files) == expected

def test_merkle_pair():
    files = {
        "a.txt": "hashA",
        "b.txt": "hashB"
    }
    # Sorted: a.txt, b.txt
    leafA = calculate_string_hash("a.txt:hashA")
    leafB = calculate_string_hash("b.txt:hashB")
    expected = calculate_string_hash(leafA + leafB)
    assert build_merkle_root(files) == expected

def test_merkle_determinism():
    files1 = {"b.txt": "hash", "a.txt": "hash"}
    files2 = {"a.txt": "hash", "b.txt": "hash"}
    assert build_merkle_root(files1) == build_merkle_root(files2)
