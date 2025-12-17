"""Tests for deduplication key generation."""
import unittest
from datetime import datetime
from unittest.mock import patch

from src.common.dedup import dedup_key


class TestDedup(unittest.TestCase):
    """Test deduplication key generation."""
    
    def test_dedup_key_basic(self):
        """Test basic dedup key generation."""
        alert = {
            "rule": {"id": "5503"},
            "agent": {"id": "001"},
            "srcip": "192.168.1.100",
        }
        
        key = dedup_key(alert)
        
        self.assertIsInstance(key, str)
        self.assertEqual(len(key), 16)  # 16 hex chars
        self.assertTrue(all(c in "0123456789abcdef" for c in key))
    
    def test_dedup_key_deterministic(self):
        """Test that same alert produces same key (on same day)."""
        alert = {
            "rule": {"id": "5503"},
            "agent": {"id": "001"},
            "srcip": "192.168.1.100",
        }
        
        key1 = dedup_key(alert)
        key2 = dedup_key(alert)
        
        self.assertEqual(key1, key2)
    
    def test_dedup_key_different_rules(self):
        """Test different rule IDs produce different keys."""
        alert1 = {
            "rule": {"id": "5503"},
            "agent": {"id": "001"},
            "srcip": "192.168.1.100",
        }
        alert2 = {
            "rule": {"id": "5504"},
            "agent": {"id": "001"},
            "srcip": "192.168.1.100",
        }
        
        key1 = dedup_key(alert1)
        key2 = dedup_key(alert2)
        
        self.assertNotEqual(key1, key2)
    
    def test_dedup_key_missing_fields(self):
        """Test dedup key with missing fields."""
        alert = {
            "rule": {"id": "5503"},
            # Missing agent and srcip
        }
        
        key = dedup_key(alert)
        
        self.assertIsInstance(key, str)
        self.assertEqual(len(key), 16)


if __name__ == "__main__":
    unittest.main()

