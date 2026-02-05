# Contributing to membranes

Thanks for your interest in making AI agents safer! membranes is open to contributions of all kinds.

## Ways to Contribute

### 🔍 New Detection Patterns (Most Valuable!)

Found a prompt injection technique that membranes doesn't catch? This is the single most valuable contribution you can make.

1. Add your pattern to `patterns/injection_patterns.yaml`
2. Follow the existing format:

```yaml
- name: descriptive_name
  category: identity_hijack | instruction_override | hidden_payload | extraction_attempt | manipulation | encoding_abuse
  severity: critical | high | medium | low
  description: "What this pattern catches"
  patterns:
    - "(?i)your regex pattern here"
```

3. Add a test case in `tests/test_scanner.py`
4. Submit a PR!

**Tips:**
- Use `(?i)` for case-insensitive matching
- Test against false positives — make sure normal text doesn't trigger it
- Include a real-world example of the attack in your PR description

### 🐛 Bug Reports & False Positives

- **False positives** (safe content flagged as a threat) — open an issue with the content that was incorrectly flagged
- **False negatives** (attacks that slip through) — open an issue or submit a pattern fix
- **Bugs** — open an issue with reproduction steps

### 🔌 Framework Integrations

Help connect membranes to popular AI frameworks:
- LangChain, CrewAI, AutoGen, OpenClaw
- FastAPI / Flask middleware
- Anything that processes untrusted content

### 📖 Documentation

- Improve examples and guides
- Add integration tutorials
- Fix typos or unclear explanations

### 🧪 Tests

- More edge cases
- Performance benchmarks
- Cross-platform testing

## Development Setup

```bash
# Clone the repo
git clone https://github.com/thebearwithabite/membranes.git
cd membranes

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
python -m pytest

# Run linting
ruff check src/
black --check src/
```

## Pull Request Process

1. Fork the repo and create a feature branch from `main`
2. Make your changes
3. Add or update tests as needed
4. Run `python -m pytest` and make sure everything passes
5. Open a PR with a clear description of what you changed and why

We aim to review PRs within a few days. Don't worry about making it perfect — we're happy to iterate!

## Code Style

- We use **Black** for formatting (line length 100)
- We use **Ruff** for linting
- Type hints are encouraged but not required
- Clear variable names > clever code

## Pattern Guidelines

When adding detection patterns:

- **Precision over recall** — it's better to miss an edge case than to flag legitimate content
- **Document the attack** — explain what real-world scenario this pattern defends against
- **Test both ways** — include positive (should detect) and negative (should not detect) test cases
- **Consider evasion** — think about how an attacker might modify the payload to bypass your pattern

## Community

- Be kind and constructive
- All skill levels welcome
- Questions are contributions too — they help us improve docs

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
