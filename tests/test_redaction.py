"""Tests for PII redaction."""
import unittest

from src.common.redaction import Redactor


class TestRedaction(unittest.TestCase):
    """Test PII redaction."""
    
    def test_redact_email(self):
        """Test email redaction."""
        redactor = Redactor()
        text = "Contact admin@example.com for support"
        
        redacted, mapping = redactor.redact(text)
        
        self.assertNotIn("admin@example.com", redacted)
        self.assertIn("[EMAIL_", redacted)
        self.assertIn("admin@example.com", mapping.values())
    
    def test_redact_ip(self):
        """Test IP address redaction."""
        redactor = Redactor()
        text = "Source IP: 192.168.1.100"
        
        redacted, mapping = redactor.redact(text)
        
        self.assertNotIn("192.168.1.100", redacted)
        self.assertIn("[IP_", redacted)
        self.assertIn("192.168.1.100", mapping.values())
    
    def test_restore(self):
        """Test restoration of redacted text."""
        redactor = Redactor()
        text = "Email: user@example.com from 10.0.0.1"
        
        redacted, mapping = redactor.redact(text)
        restored = redactor.restore(redacted, mapping)
        
        self.assertEqual(text, restored)
    
    def test_redact_multiple(self):
        """Test redaction of multiple PII items."""
        redactor = Redactor()
        text = "User admin@example.com from 192.168.1.100 connected"
        
        redacted, mapping = redactor.redact(text)
        
        # Should have multiple redactions
        self.assertGreater(len(mapping), 1)
        self.assertNotIn("admin@example.com", redacted)
        self.assertNotIn("192.168.1.100", redacted)


if __name__ == "__main__":
    unittest.main()

