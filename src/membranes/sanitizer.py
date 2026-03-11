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
    - REMOVE: Delete the threatening content entirely (no trace)
    - PLACEHOLDER: Replace with neutral marker [CONTENT REMOVED: category]
    - BRACKET: Wrap in visible brackets [BLOCKED: ...] (shows original text)
    - DEFANG: Modify to be non-executable (e.g., add spaces)
    - ESCAPE: HTML/markdown escape the content
    """
    
    # Strategy mapping based on severity and use case:
    # REMOVE: Jailbreak commands with no legitimate use (e.g., "IGNORE ALL PREVIOUS")
    # PLACEHOLDER: Technical exploits, no reason to preserve original text
    # DEFANG: Encoding/obfuscation that might have legitimate educational use
    # BRACKET: Social engineering patterns that might be legitimate context
    DEFAULT_STRATEGIES = {
        # === CRITICAL - Technical Exploits (PLACEHOLDER) ===
        # No legitimate reason to preserve these; replace with placeholder
        "delimiter_hijacking": "placeholder",
        "steganography": "placeholder",
        "code_execution": "placeholder",
        "hidden_payload": "placeholder",
        "tool_invocation": "placeholder",
        "adversarial_suffix": "placeholder",
        "polyglot_injection": "placeholder",
        "context_poisoning": "placeholder",
        "chain_reasoning_manipulation": "placeholder",
        "markdown_exfiltration": "placeholder",
        "delimiter_hijack": "placeholder",  # Alias if used
        
        # === HIGH - Jailbreaks & Overrides (PLACEHOLDER) ===
        # Core jailbreak patterns that should never reach the LLM
        "instruction_override": "placeholder",
        "identity_hijack": "placeholder",
        "cognitive_hijacking": "placeholder",
        "refusal_suppression": "placeholder",
        "multi_turn_attack": "placeholder",
        "extraction_attempt": "placeholder",
        "completion_forcing": "placeholder",
        
        # === MEDIUM - Obfuscation (DEFANG) ===
        # Break patterns but preserve some context for debugging/learning
        "encoding_abuse": "defang",
        "token_smuggling": "defang",
        "math_exfiltration": "defang",
        "homoglyph_attack": "defang",
        "normalization_attack": "defang",
        
        # === LOW - Social Engineering (PLACEHOLDER) ===
        # Even low-severity social engineering should use placeholder
        # as it often contains jailbreak keywords
        "manipulation": "placeholder",
        
        # === Compound threats (PLACEHOLDER) ===
        "compound": "placeholder",
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
    
    def _get_placeholder(self, category: str) -> str:
        """Replace threat with neutral placeholder (no original text exposed)."""
        return f"[CONTENT REMOVED: {category}]"
    
    def _get_bracket(self, match_text: str, threat_name: str) -> str:
        """Wrap threatening content in visible brackets."""
        return f"[⚠️ BLOCKED ({threat_name}): {match_text[:50]}{'...' if len(match_text) > 50 else ''}]"
    
    def _get_defang(self, match_text: str) -> str:
        """Defang by inserting zero-width spaces or other neutralizers."""
        # Insert visible markers to break the pattern
        defanged = match_text.replace(" ", " · ")
        return f"[DEFANGED: {defanged}]"
    
    def _get_escape(self, match_text: str) -> str:
        """HTML/markdown escape the threatening content."""
        return (match_text
            .replace("&", "&")
            .replace("<", "<")
            .replace(">", ">")
            .replace("`", "\\`")
            .replace("*", "\\*")
            .replace("_", "\\_")
        )
    
    def _filter_overlapping_threats(self, threats: List) -> List:
        """Filter out overlapping threats, keeping the most severe/longest match."""
        if not threats:
            return []
        
        # Sort by offset (ascending), then by length (descending)
        sorted_threats = sorted(threats, key=lambda t: (t.offset, -len(t.matched_text)))
        
        filtered = []
        last_end = -1
        
        for threat in sorted_threats:
            threat_start = threat.offset
            threat_end = threat.offset + len(threat.matched_text)
            
            # Check if this threat overlaps with the previous one
            if threat_start >= last_end:
                filtered.append(threat)
                last_end = threat_end
            # If overlapping, skip this threat (we already kept the longer one)
        
        return filtered
    
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
        
        # Filter out overlapping threats to avoid double-processing
        threats = self._filter_overlapping_threats(threats)
        
        # Sort threats by offset (descending) to process from end to start
        # This preserves offsets as we modify the string
        sorted_threats = sorted(threats, key=lambda t: t.offset, reverse=True)
        
        for threat in sorted_threats:
            strategy = self.strategies.get(threat.category, "bracket")
            replacement = match_text = threat.matched_text
            
            if strategy == "remove":
                replacement = ""
            elif strategy == "placeholder":
                replacement = self._get_placeholder(threat.category)
            elif strategy == "bracket":
                replacement = self._get_bracket(threat.matched_text, threat.name)
            elif strategy == "defang":
                replacement = self._get_defang(threat.matched_text)
            elif strategy == "escape":
                replacement = self._get_escape(threat.matched_text)
                
            # Apply replacement using offsets (safe for reverse iteration)
            start = threat.offset
            end = start + len(match_text)
            content = content[:start] + replacement + content[end:]
        
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
        
        # Filter out overlapping threats
        threats = self._filter_overlapping_threats(threats)
        
        # Process other threats
        sorted_threats = sorted(threats, key=lambda t: t.offset, reverse=True)
        
        for threat in sorted_threats:
            strategy = self.strategies.get(threat.category, "bracket")
            replacement = match_text = threat.matched_text
            
            if strategy == "remove":
                replacement = ""
            elif strategy == "placeholder":
                replacement = self._get_placeholder(threat.category)
            elif strategy == "bracket":
                replacement = self._get_bracket(threat.matched_text, threat.name)
            elif strategy == "defang":
                replacement = self._get_defang(threat.matched_text)
            elif strategy == "escape":
                replacement = self._get_escape(threat.matched_text)

            changes.append({
                "type": strategy,
                "offset": threat.offset,
                "threat": threat.name,
                "category": threat.category,
                "matched": threat.matched_text[:50]
            })
            
            # Apply replacement using offsets
            start = threat.offset
            end = start + len(match_text)
            content = content[:start] + replacement + content[end:]
        
        # Calculate actual removed count (including placeholder and remove strategies)
        removed_count = len([c for c in changes if c.get("type") in ("remove", "placeholder")])
        
        return SanitizationResult(
            original=original,
            sanitized=content,
            changes=changes,
            removed_count=removed_count
        )


def quick_sanitize(content: str) -> str:
    """
    Quick sanitization with default settings.
    
    Usage:
        from membranes import quick_sanitize
        clean = quick_sanitize(potentially_dangerous_content)
    """
    return Sanitizer().sanitize(content)
