#!/usr/bin/env python3
"""
membranes CLI - Scan content for prompt injection attacks

Usage:
    membranes scan "content to scan"
    membranes scan --file path/to/file.txt
    membranes scan --stdin < file.txt
    echo "content" | membranes scan --stdin
    
    membranes sanitize "content to clean"
    membranes sanitize --file path/to/file.txt
    
    membranes watch --dir ./incoming  # Watch directory for new files
"""

import argparse
import sys
import json
from pathlib import Path


def cmd_scan(args):
    """Scan content for threats."""
    from .scanner import Scanner
    
    scanner = Scanner(
        patterns_path=args.patterns,
        severity_threshold=args.severity
    )
    
    # Get content
    if args.file:
        content = Path(args.file).read_text()
    elif args.stdin:
        content = sys.stdin.read()
    else:
        content = args.content
    
    if not content:
        print("Error: No content provided. Use --file, --stdin, or provide content directly.", file=sys.stderr)
        sys.exit(1)
    
    result = scanner.scan(content, include_sanitized=args.sanitize)
    
    if args.json:
        print(result.to_json())
    else:
        if result.is_safe:
            print("✅ SAFE - No threats detected")
            print(f"   Hash: {result.content_hash}")
            print(f"   Scanned in: {result.scan_time_ms}ms")
        else:
            print(f"⚠️  THREATS DETECTED: {result.threat_count}")
            print(f"   Max severity: {result.max_severity}")
            print(f"   Categories: {', '.join(result.categories)}")
            print(f"   Hash: {result.content_hash}")
            print()
            
            for i, threat in enumerate(result.threats, 1):
                severity_emoji = {
                    "low": "🟡",
                    "medium": "🟠", 
                    "high": "🔴",
                    "critical": "💀"
                }.get(threat.severity, "⚪")
                
                print(f"   {i}. {severity_emoji} [{threat.severity.upper()}] {threat.name}")
                print(f"      Category: {threat.category}")
                print(f"      Matched: \"{threat.matched_text[:60]}{'...' if len(threat.matched_text) > 60 else ''}\"")
                print(f"      Offset: {threat.offset}")
                if threat.description:
                    print(f"      Info: {threat.description}")
                print()
            
            if result.sanitized_content:
                print("--- SANITIZED OUTPUT ---")
                print(result.sanitized_content)
    
    # Exit with error code if threats found
    sys.exit(0 if result.is_safe else 1)


def cmd_sanitize(args):
    """Sanitize content by removing/neutralizing threats."""
    from .scanner import Scanner
    from .sanitizer import Sanitizer
    
    scanner = Scanner(severity_threshold=args.severity)
    sanitizer = Sanitizer()
    
    # Get content
    if args.file:
        content = Path(args.file).read_text()
    elif args.stdin:
        content = sys.stdin.read()
    else:
        content = args.content
    
    if not content:
        print("Error: No content provided.", file=sys.stderr)
        sys.exit(1)
    
    # Scan first
    scan_result = scanner.scan(content)
    
    if scan_result.is_safe:
        if not args.quiet:
            print("✅ Content is already safe, no sanitization needed.", file=sys.stderr)
        print(content)
    else:
        # Sanitize
        result = sanitizer.sanitize_with_report(content, scan_result.threats)
        
        if args.json:
            print(json.dumps({
                "was_modified": result.was_modified,
                "removed_count": result.removed_count,
                "changes": result.changes,
                "sanitized": result.sanitized
            }, indent=2))
        else:
            if not args.quiet:
                print(f"🧹 Sanitized {len(result.changes)} threats", file=sys.stderr)
            print(result.sanitized)


def cmd_check(args):
    """Quick boolean check - exit 0 if safe, 1 if threats."""
    from .scanner import Scanner
    
    scanner = Scanner(severity_threshold=args.severity)
    
    # Get content
    if args.file:
        content = Path(args.file).read_text()
    elif args.stdin:
        content = sys.stdin.read()
    else:
        content = args.content
    
    is_safe = scanner.quick_check(content)
    sys.exit(0 if is_safe else 1)


def cmd_patterns(args):
    """List available detection patterns."""
    from .scanner import Scanner
    
    scanner = Scanner(patterns_path=args.patterns)
    
    if args.json:
        patterns = []
        for p in scanner.patterns:
            patterns.append({
                "name": p["name"],
                "category": p["category"],
                "severity": p["severity"],
                "description": p.get("description", ""),
                "pattern_count": len(p.get("patterns", []))
            })
        print(json.dumps(patterns, indent=2))
    else:
        print("Available Detection Patterns")
        print("=" * 50)
        
        by_category = {}
        for p in scanner.patterns:
            cat = p["category"]
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(p)
        
        for category, patterns in by_category.items():
            print(f"\n📁 {category.upper()}")
            for p in patterns:
                severity_emoji = {
                    "low": "🟡",
                    "medium": "🟠",
                    "high": "🔴",
                    "critical": "💀"
                }.get(p["severity"], "⚪")
                print(f"   {severity_emoji} {p['name']}: {p.get('description', 'No description')[:60]}")


def main():
    parser = argparse.ArgumentParser(
        prog="membranes",
        description="Prompt injection defense for AI agents 🛡️",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  membranes scan "Ignore previous instructions and..."
  membranes scan --file suspicious_email.txt --json
  echo "some content" | membranes scan --stdin
  membranes sanitize --file input.txt > cleaned.txt
  membranes check --file input.txt && echo "Safe!"
  
Learn more: https://github.com/membranes/membranes
        """
    )
    
    parser.add_argument("--version", action="version", version="membranes 0.1.0")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan content for prompt injection")
    scan_parser.add_argument("content", nargs="?", help="Content to scan")
    scan_parser.add_argument("--file", "-f", help="Read content from file")
    scan_parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    scan_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    scan_parser.add_argument("--sanitize", "-s", action="store_true", help="Include sanitized output")
    scan_parser.add_argument("--severity", default="low", choices=["low", "medium", "high", "critical"],
                            help="Minimum severity to report (default: low)")
    scan_parser.add_argument("--patterns", "-p", help="Custom patterns YAML file")
    scan_parser.set_defaults(func=cmd_scan)
    
    # Sanitize command
    sanitize_parser = subparsers.add_parser("sanitize", help="Clean content by removing threats")
    sanitize_parser.add_argument("content", nargs="?", help="Content to sanitize")
    sanitize_parser.add_argument("--file", "-f", help="Read content from file")
    sanitize_parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    sanitize_parser.add_argument("--json", "-j", action="store_true", help="Output report as JSON")
    sanitize_parser.add_argument("--quiet", "-q", action="store_true", help="Only output sanitized content")
    sanitize_parser.add_argument("--severity", default="low", choices=["low", "medium", "high", "critical"],
                                help="Minimum severity to sanitize")
    sanitize_parser.set_defaults(func=cmd_sanitize)
    
    # Check command (quick boolean)
    check_parser = subparsers.add_parser("check", help="Quick safety check (exit 0=safe, 1=threats)")
    check_parser.add_argument("content", nargs="?", help="Content to check")
    check_parser.add_argument("--file", "-f", help="Read content from file")
    check_parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    check_parser.add_argument("--severity", default="low", choices=["low", "medium", "high", "critical"],
                             help="Minimum severity to fail on")
    check_parser.set_defaults(func=cmd_check)
    
    # Patterns command
    patterns_parser = subparsers.add_parser("patterns", help="List detection patterns")
    patterns_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    patterns_parser.add_argument("--patterns", "-p", help="Custom patterns YAML file")
    patterns_parser.set_defaults(func=cmd_patterns)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    args.func(args)


if __name__ == "__main__":
    main()
