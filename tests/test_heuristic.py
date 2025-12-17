"""Tests for heuristic scoring."""
import unittest

from src.analyzer.heuristic import score


class TestHeuristic(unittest.TestCase):
    """Test heuristic scoring."""
    
    def test_score_basic(self):
        """Test basic scoring."""
        alert = {
            "rule": {
                "id": "5503",
                "level": 10,
                "groups": [],
            },
        }
        
        result = score(alert)
        
        self.assertIsInstance(result, float)
        self.assertGreaterEqual(result, 0.0)
        self.assertLessEqual(result, 1.0)
    
    def test_score_level_15(self):
        """Test score for level 15 alert."""
        alert = {
            "rule": {
                "id": "5503",
                "level": 15,
                "groups": [],
            },
        }
        
        result = score(alert)
        
        self.assertAlmostEqual(result, 1.0, places=1)
    
    def test_score_level_7(self):
        """Test score for level 7 alert."""
        alert = {
            "rule": {
                "id": "5503",
                "level": 7,
                "groups": [],
            },
        }
        
        result = score(alert)
        
        # Should be approximately 7/15 = 0.467
        self.assertAlmostEqual(result, 0.467, places=2)
    
    def test_score_high_severity_group(self):
        """Test score with high-severity rule group."""
        alert = {
            "rule": {
                "id": "5503",
                "level": 10,
                "groups": ["authentication_failed"],
            },
        }
        
        result = score(alert)
        
        # Should have bonus
        self.assertGreater(result, 10 / 15.0)
        self.assertLessEqual(result, 1.0)
    
    def test_score_bruteforce_group(self):
        """Test score with bruteforce group."""
        alert = {
            "rule": {
                "id": "5503",
                "level": 12,
                "groups": ["bruteforce"],
            },
        }
        
        result = score(alert)
        
        # Should have bonus
        self.assertGreater(result, 12 / 15.0)
    
    def test_score_no_level(self):
        """Test score with missing level."""
        alert = {
            "rule": {
                "id": "5503",
                "groups": [],
            },
        }
        
        result = score(alert)
        
        self.assertEqual(result, 0.0)


if __name__ == "__main__":
    unittest.main()

