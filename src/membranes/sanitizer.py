"""
membranes.sanitizer - Clean dangerous content while preserving benign parts
"""

import re
import unicodedata
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class SanitizationResult:
    """Result of sanitizing content."""
    original: str
    sanitized: str
    changes: List[Dict]
    removed_count: int
    
    @property
    def was_modified(self) -> bool:
        return self.original != self.sanitized


class Sanitizer:
    """
    Sanitizes content by removing or neutralizing detected threats.
    
    Strategies:
    - REMOVE: Delete the threatening content entirely
    - BRACKET: Wrap in visible brackets [BLOCKED: ...]
    - DEFANG: Modify to be non-executable (e.g., add spaces)
    - ESCAPE: HTML/markdown escape the content
    """
    
    DEFAULT_STRATEGIES = {
        "identity_hijack": "bracket",
        "instruction_override": "bracket", 
        "hidden_payload": "remove",
        "extraction_attempt": "defang",
        "manipulation": "bracket",
        "encoding_abuse": "remove",
        "compound": "bracket"
    }
    
    def __init__(self, strategies: Optional[Dict[str, str]] = None):
        """
        Initialize sanitizer with optional custom strategies.
        
        Args:
            strategies: Dict mapping category to strategy (remove/bracket/defang/escape)
        """
        self.strategies = {**self.DEFAULT_STRATEGIES}
        if strategies:
            self.strategies.update(strategies)
    
    def _remove_invisible_unicode(self, content: str) -> Tuple[str, List[Dict]]:
        """Remove invisible Unicode characters."""
        changes = []
        result = []
        
        for i, char in enumerate(content):
            cat = unicodedata.category(char)
            # Keep normal whitespace and printable characters
            if cat in ('Cf', 'Co') or (cat == 'Zs' and ord(char) > 127):
                changes.append({
                    "type": "remove",
                    "offset": i,
                    "removed": f"U+{ord(char):04X}",
                    "reason": "invisible_unicode"
                })
            else:
                result.append(char)
        
        return ''.join(result), changes
    
    def _bracket_threat(self, content: str, match_text: str, threat_name: str) -> str:
        """Wrap threatening content in visible brackets."""
        replacement = f"[⚠️ BLOCKED ({threat_name}): {match_text[:50]}{'...' if len(match_text) > 50 else ''}]"
        return content.replace(match_text, replacement, 1)
    
    def _defang_threat(self, content: str, match_text: str) -> str:
        """Defang by inserting zero-width spaces or other neutralizers."""
        # Insert visible markers to break the pattern
        defanged = match_text.replace(" ", " · ")
        return content.replace(match_text, f"[DEFANGED: {defanged}]", 1)
    
    def _escape_threat(self, content: str, match_text: str) -> str:
        """HTML/markdown escape the threatening content."""
        escaped = (match_text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("`", "\\`")
            .replace("*", "\\*")
            .replace("_", "\\_")
        )
        return content.replace(match_text, escaped, 1)
    
    def sanitize(self, content: str, threats: Optional[List] = None) -> str:
        """
        Sanitize content by neutralizing detected threats.
        
        Args:
            content: Original content
            threats: List of Threat objects (if None, will scan first)
            
        Returns:
            Sanitized content string
        """
        if threats is None:
            from .scanner import Scanner
            result = Scanner().scan(content)
            threats = result.threats
        
        # First pass: remove invisible Unicode
        content, _ = self._remove_invisible_unicode(content)
        
        # Sort threats by offset (descending) to process from end to start
        # This preserves offsets as we modify the string
        sorted_threats = sorted(threats, key=lambda t: t.offset, reverse=True)
        
        for threat in sorted_threats:
            strategy = self.strategies.get(threat.category, "bracket")
            
            if strategy == "remove":
                content = content.replace(threat.matched_text, "", 1)
            elif strategy == "bracket":
                content = self._bracket_threat(content, threat.matched_text, threat.name)
            elif strategy == "defang":
                content = self._defang_threat(content, threat.matched_text)
            elif strategy == "escape":
                content = self._escape_threat(content, threat.matched_text)
        
        return content
    
    def sanitize_with_report(self, content: str, threats: Optional[List] = None) -> SanitizationResult:
        """
        Sanitize content and return detailed report.
        
        Returns:
            SanitizationResult with original, sanitized, and change log
        """
        original = content
        
        if threats is None:
            from .scanner import Scanner
            result = Scanner().scan(content)
            threats = result.threats
        
        changes = []
        
        # Remove invisible Unicode first
        content, unicode_changes = self._remove_invisible_unicode(content)
        changes.extend(unicode_changes)
        
        # Process other threats
        sorted_threats = sorted(threats, key=lambda t: t.offset, reverse=True)
        
        for threat in sorted_threats:
            strategy = self.strategies.get(threat.category, "bracket")
            changes.append({
                "type": strategy,
                "offset": threat.offset,
                "threat": threat.name,
                "category": threat.category,
                "matched": threat.matched_text[:50]
            })
            
            if strategy == "remove":
                content = content.replace(threat.matched_text, "", 1)
            elif strategy == "bracket":
                content = self._bracket_threat(content, threat.matched_text, threat.name)
            elif strategy == "defang":
                content = self._defang_threat(content, threat.matched_text)
            elif strategy == "escape":
                content = self._escape_threat(content, threat.matched_text)
        
        return SanitizationResult(
            original=original,
            sanitized=content,
            changes=changes,
            removed_count=len([c for c in changes if c.get("type") == "remove"])
        )


def quick_sanitize(content: str) -> str:
    """
    Quick sanitization with default settings.
    
    Usage:
        from membranes import quick_sanitize
        clean = quick_sanitize(potentially_dangerous_content)
    """
    return Sanitizer().sanitize(content)
