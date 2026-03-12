import pytest
import os
import zipfile
import tarfile
from core.vfs.directory import DirectoryVFS
from core.vfs.archive import ArchiveVFS
from core.ingest import get_vfs

@pytest.fixture
def sample_dir(tmp_path):
    d = tmp_path / "evidence"
    d.mkdir()
    (d / "file1.txt").write_text("content1")
    (d / "subdir").mkdir()
    (d / "subdir" / "file2.txt").write_text("content2")
    return str(d)

@pytest.fixture
def sample_zip(tmp_path):
    z_path = tmp_path / "evidence.zip"
    with zipfile.ZipFile(z_path, 'w') as zf:
        zf.writestr("file1.txt", "content1")
        zf.writestr("subdir/file2.txt", "content2")
    return str(z_path)

def test_directory_vfs(sample_dir):
    vfs = DirectoryVFS(sample_dir)
    
    # Test Listing
    assert "file1.txt" in vfs.listdir("")
    assert "subdir" in vfs.listdir("")
    
    # Test Read
    assert vfs.read_bytes("file1.txt") == b"content1"
    assert vfs.read_bytes("subdir/file2.txt") == b"content2"
    
    # Test Stat
    stats = vfs.stat("file1.txt")
    assert stats['size'] == 8
    
    # Test Walk
    walk_res = list(vfs.walk(""))
    # Expect root, subdir
    assert len(walk_res) >= 2

def test_archive_vfs_zip(sample_zip):
    vfs = ArchiveVFS(sample_zip)
    
    # Test Listing
    assert "file1.txt" in vfs.listdir("")
    assert "subdir" in vfs.listdir("")
    
    # Test Read
    assert vfs.read_bytes("file1.txt") == b"content1"
    assert vfs.read_bytes("subdir/file2.txt") == b"content2"
    
    # Test Is Dir
    assert vfs.is_dir("subdir")
    assert not vfs.is_dir("file1.txt")

def test_readonly_enforcement(sample_dir):
    vfs = DirectoryVFS(sample_dir)
    with pytest.raises(PermissionError):
        vfs.open("file1.txt", "w")
    with pytest.raises(PermissionError):
        vfs.open("file1.txt", "a")
    with pytest.raises(PermissionError):
        vfs.open("file1.txt", "r+")

def test_path_traversal_protection(sample_dir):
    vfs = DirectoryVFS(sample_dir)
    # Attempt to read outside evidence root
    # Valid relative path logic might act differently depending on normalization
    # But absolute traversal should fail
    
    with pytest.raises(PermissionError):
        vfs.open("../../../etc/passwd")

def test_factory(sample_dir, sample_zip):
    assert isinstance(get_vfs(sample_dir), DirectoryVFS)
    assert isinstance(get_vfs(sample_zip), ArchiveVFS)
