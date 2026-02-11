"""
membranes.scanner - Core scanning logic
"""

import re
import hashlib
import os
import unicodedata
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path
import yaml
import json


@dataclass
class Threat:
    """A detected threat in the scanned content."""
    name: str
    category: str
    severity: str  # low, medium, high, critical
    matched_text: str
    offset: int
    pattern: str
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "matched_text": self.matched_text[:100] + "..." if len(self.matched_text) > 100 else self.matched_text,
            "offset": self.offset,
            "description": self.description
        }


@dataclass 
class ScanResult:
    """Result of scanning content for prompt injection."""
    is_safe: bool
    content_hash: str
    threats: List[Threat] = field(default_factory=list)
    sanitized_content: Optional[str] = None
    scan_time_ms: float = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def threat_count(self) -> int:
        return len(self.threats)
    
    @property
    def max_severity(self) -> Optional[str]:
        if not self.threats:
            return None
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return max(self.threats, key=lambda t: severity_order.get(t.severity, 0)).severity
    
    @property
    def categories(self) -> List[str]:
        return list(set(t.category for t in self.threats))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "content_hash": self.content_hash,
            "threat_count": self.threat_count,
            "max_severity": self.max_severity,
            "categories": self.categories,
            "threats": [t.to_dict() for t in self.threats],
            "scan_time_ms": self.scan_time_ms
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class Scanner:
    """
    Scans content for prompt injection attacks.
    
    Args:
        patterns_path: Path to YAML patterns file. Uses built-in patterns if None.
        severity_threshold: Minimum severity to flag. Options: low, medium, high, critical
        custom_patterns: Additional patterns to add
        max_content_length: Maximum content length to scan (ReDoS protection)
        pattern_timeout_ms: Timeout per pattern in milliseconds (ReDoS protection)
    """
    
    SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    
    # High-risk patterns that need pre-validation (ReDoS protection)
    HIGH_RISK_PATTERNS = {
        "adversarial_suffix_patterns": ["!", " "],  # Must contain ! or space
        "authority_impersonation": ["OpenAI", "Anthropic", "engineer", "developer", "admin", "authorized", "code"],
        "token_smuggling_repetition": [],  # Always run - has internal safeguards
    }
    
    def __init__(
        self,
        patterns_path: Optional[str] = None,
        severity_threshold: str = "low",
        custom_patterns: Optional[List[Dict]] = None,
        max_content_length: int = 50000,  # 50KB ReDoS protection
        pattern_timeout_ms: float = 100.0  # 100ms per pattern timeout
    ):
        self.severity_threshold = severity_threshold
        self.max_content_length = max_content_length
        self.pattern_timeout_ms = pattern_timeout_ms
        self.patterns = []
        self.compound_threats = []
        
        # Load patterns
        if patterns_path:
            self._load_patterns(patterns_path)
        else:
            # Load built-in patterns
            # 1. Check environment variable (useful for Docker/ConfigMaps)
            env_path = os.getenv("MEMBRANES_PATTERNS_PATH")
            # 2. Use package-relative path (works in both dev and installed modes)
            pkg_path = Path(__file__).parent / "injection_patterns.yaml"

            if env_path and Path(env_path).exists():
                self._load_patterns(env_path)
            elif pkg_path.exists():
                self._load_patterns(str(pkg_path))
            else:
                raise FileNotFoundError(
                    f"Could not find injection_patterns.yaml. "
                    f"Searched at: {pkg_path}. "
                    f"Set MEMBRANES_PATTERNS_PATH env var to specify a custom location."
                )
        
        # Add custom patterns
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        
        # Compile regex patterns for performance
        self._compile_patterns()
    
    def _should_skip_pattern(self, pattern_name: str, content: str) -> bool:
        """
        Pre-validate high-risk patterns to avoid ReDoS.
        Returns True if pattern should be skipped.
        """
        if pattern_name not in self.HIGH_RISK_PATTERNS:
            return False
        
        required_substrings = self.HIGH_RISK_PATTERNS[pattern_name]
        
        # If no required substrings defined, always run the pattern
        if not required_substrings:
            return False
        
        # Check if any required substring is present
        content_lower = content.lower()
        return not any(req.lower() in content_lower for req in required_substrings)
    
    def _safe_regex_search(self, pattern, content: str, pattern_name: str) -> List[re.Match]:
        """
        Perform regex search with ReDoS protection.
        Uses timeout if signal module is available (Unix), otherwise truncates content.
        """
        matches = []
        
        # Skip high-risk patterns that don't have required substrings
        if self._should_skip_pattern(pattern_name, content):
            return matches
        
        # Truncate content if too long (ReDoS protection)
        if len(content) > self.max_content_length:
            content = content[:self.max_content_length]
        
        try:
            # Try to use signal-based timeout on Unix systems
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError(f"Pattern {pattern_name} exceeded {self.pattern_timeout_ms}ms")
            
            # Set alarm for pattern timeout (convert ms to seconds)
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.setitimer(signal.ITIMER_REAL, self.pattern_timeout_ms / 1000.0)
            
            try:
                matches = list(pattern.finditer(content))
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)  # Cancel alarm
                signal.signal(signal.SIGALRM, old_handler)
                
        except (ImportError, AttributeError):
            # Windows or signal not available - use simple approach with length limiting
            matches = list(pattern.finditer(content))
        except TimeoutError:
            # Pattern timed out - log warning and return empty matches
            print(f"Warning: Pattern '{pattern_name}' timed out after {self.pattern_timeout_ms}ms (ReDoS protection)")
            matches = []
        
        return matches
    
    def _load_patterns(self, path: str) -> None:
        """Load patterns from YAML file."""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        self.patterns = data.get("patterns", [])
        self.compound_threats = data.get("compound_threats", [])
    
    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for pattern_def in self.patterns:
            compiled = []
            for p in pattern_def.get("patterns", []):
                try:
                    compiled.append(re.compile(p))
                except re.error as e:
                    print(f"Warning: Invalid regex pattern '{p}': {e}")
            pattern_def["_compiled"] = compiled
    
    def _check_severity(self, severity: str) -> bool:
        """Check if severity meets threshold."""
        return self.SEVERITY_ORDER.get(severity, 0) >= self.SEVERITY_ORDER.get(self.severity_threshold, 0)
    
    def _detect_invisible_unicode(self, content: str) -> List[Threat]:
        """Detect suspicious invisible Unicode characters."""
        threats = []
        
        # Categories of suspicious characters
        suspicious_categories = {
            'Cf': 'format character',
            'Zs': 'space separator', 
            'Co': 'private use'
        }
        
        for i, char in enumerate(content):
            cat = unicodedata.category(char)
            if cat in suspicious_categories and ord(char) not in [32, 10, 13, 9]:  # Allow normal whitespace
                # Check if it's actually suspicious (not just a regular space)
                if ord(char) > 127 or cat == 'Cf':
                    threats.append(Threat(
                        name="invisible_unicode",
                        category="hidden_payload",
                        severity="high",
                        matched_text=f"U+{ord(char):04X} ({suspicious_categories[cat]})",
                        offset=i,
                        pattern="unicode_category_check",
                        description=f"Invisible Unicode character detected: {unicodedata.name(char, 'UNKNOWN')}"
                    ))
        
        return threats
    
    def _detect_base64_hidden(self, content: str) -> List[Threat]:
        """Detect and optionally decode suspicious base64 content."""
        import base64
        threats = []
        
        # Find potential base64 strings
        b64_pattern = re.compile(r'[A-Za-z0-9+/=]{40,}')
        
        for match in b64_pattern.finditer(content):
            b64_str = match.group()
            try:
                # Try to decode
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                
                # Check if decoded content contains suspicious patterns
                suspicious_keywords = ['ignore', 'instruction', 'prompt', 'system', 'override', 'forget']
                if any(kw in decoded.lower() for kw in suspicious_keywords):
                    threats.append(Threat(
                        name="base64_hidden_instruction",
                        category="hidden_payload",
                        severity="critical",
                        matched_text=b64_str[:50] + "...",
                        offset=match.start(),
                        pattern="base64_decode_check",
                        description=f"Base64 decoded to suspicious content: {decoded[:100]}"
                    ))
            except:
                pass  # Not valid base64
        
        return threats
    
    def scan(self, content: str, include_sanitized: bool = False) -> ScanResult:
        """
        Scan content for prompt injection attacks.
        
        Args:
            content: The text content to scan
            include_sanitized: If True, include sanitized version in result
            
        Returns:
            ScanResult with threats and metadata
        """
        import time
        start = time.time()
        
        threats = []
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        
        # Truncate content if too long (ReDoS protection)
        scan_content = content[:self.max_content_length] if len(content) > self.max_content_length else content
        was_truncated = len(content) > self.max_content_length
        
        # Run pattern-based detection with ReDoS protection
        for pattern_def in self.patterns:
            if not self._check_severity(pattern_def.get("severity", "low")):
                continue
            
            pattern_name = pattern_def["name"]
            
            for compiled_pattern in pattern_def.get("_compiled", []):
                # Use safe regex search with timeout and pre-validation
                matches = self._safe_regex_search(compiled_pattern, scan_content, pattern_name)
                
                for match in matches:
                    threats.append(Threat(
                        name=pattern_name,
                        category=pattern_def["category"],
                        severity=pattern_def["severity"],
                        matched_text=match.group(),
                        offset=match.start(),
                        pattern=compiled_pattern.pattern,
                        description=pattern_def.get("description", "")
                    ))
        
        # Run special detections
        threats.extend(self._detect_invisible_unicode(content))
        threats.extend(self._detect_base64_hidden(content))
        
        # Check for compound threats
        detected_categories = set(t.category for t in threats)
        for compound in self.compound_threats:
            required = set(compound.get("requires_all", []))
            if required.issubset(detected_categories):
                threats.append(Threat(
                    name=compound["name"],
                    category="compound",
                    severity=compound.get("severity", "critical"),
                    matched_text="[compound threat]",
                    offset=0,
                    pattern="compound_detection",
                    description=compound.get("description", "")
                ))
        
        scan_time = (time.time() - start) * 1000
        
        # Build result
        result = ScanResult(
            is_safe=len(threats) == 0,
            content_hash=content_hash,
            threats=threats,
            scan_time_ms=round(scan_time, 2),
            metadata={
                "content_length": len(content),
                "patterns_checked": len(self.patterns)
            }
        )
        
        # Optionally include sanitized content
        if include_sanitized and not result.is_safe:
            from .sanitizer import Sanitizer
            result.sanitized_content = Sanitizer().sanitize(content, threats)
        
        return result
    
    def scan_file(self, path: str, **kwargs) -> ScanResult:
        """Scan a file for prompt injection."""
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        return self.scan(content, **kwargs)
    
    def quick_check(self, content: str) -> bool:
        """
        Quick boolean check - is this content safe?
        
        Returns True if safe, False if threats detected.
        """
        return self.scan(content).is_safe
