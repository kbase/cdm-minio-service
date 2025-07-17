"""Tests for the minio.managers.sharing_manager module."""

from src.minio.managers.sharing_manager import SharingManager


def test_sharing_manager_imports():
    """Test that sharing manager module can be imported."""
    assert SharingManager is not None


def test_noop():
    """Simple placeholder test."""
    assert 1 == 1
