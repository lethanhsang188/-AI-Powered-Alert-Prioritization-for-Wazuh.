"""Xoá thông tin nhận dạng cá nhân (PII) trước khi xử lý bởi LLM."""
import re
from typing import Dict, Tuple


# Pattern mappings: (pattern, replacement_template)
PATTERNS = [
    # Email addresses
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_{}]'),
    # IPv4 addresses
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP_{}]'),
    # Usernames (common patterns: domain\\user, user@domain, /home/user)
    (r'\b(?:[A-Za-z0-9_\-]+(?:\\|@|/)[A-Za-z0-9_\-]+)\b', '[USER_{}]'),
    # Windows paths with usernames
    (r'C:\\Users\\[A-Za-z0-9_\-]+', '[USER_PATH_{}]'),
]


class Redactor:
    """Xoá PII khỏi văn bản đồng thời giữ mapping để có thể phục hồi."""
    
    def __init__(self):
        self.mapping: Dict[str, str] = {}
        self.counter = 0
    
    def redact(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Redact PII from text.
        
        Returns:
            (redacted_text, mapping) where mapping[token] = original_value
        """
        self.mapping.clear()
        self.counter = 0
        redacted = text
        
        for pattern, template in PATTERNS:
            matches = re.finditer(pattern, redacted, re.IGNORECASE)
            # Collect all matches first to avoid index shifting
            replacements = []
            
            for match in matches:
                original = match.group(0)
                # Check if already redacted
                if not original.startswith('[') or not original.endswith(']'):
                    self.counter += 1
                    token = template.format(chr(64 + self.counter))  # A, B, C...
                    self.mapping[token] = original
                    replacements.append((match.start(), match.end(), token))
            
            # Apply replacements in reverse order to preserve indices
            for start, end, token in reversed(replacements):
                redacted = redacted[:start] + token + redacted[end:]
        
        return redacted, self.mapping
    
    def restore(self, text: str, mapping: Dict[str, str]) -> str:
        """Restore redacted text using mapping."""
        restored = text
        for token, original in mapping.items():
            restored = restored.replace(token, original)
        return restored

