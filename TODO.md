__Pattern Refactoring (1-2 days)__

- Rewrite `adversarial_suffix_patterns` with simpler alternatives
- Optimize `authority_impersonation` (already slow at 81ms)
- Add ReDoS test suite with malicious inputs

__Long-term Hardening__

- Implement regex complexity analysis tool
- Add continuous performance benchmarks
- Consider using RE2 (Google's regex engine) which doesn't backtrack
