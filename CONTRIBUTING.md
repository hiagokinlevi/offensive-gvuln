# Contributing to offensive-gvuln

## How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes with tests
4. Ensure the test suite passes: `pytest`
5. Submit a pull request

## Guidelines

- All tools must be strictly defensive — vulnerability *management*, not exploitation
- New features require tests with ≥70% coverage
- Follow existing code style (type hints, docstrings, English)
- Commit messages: imperative mood, English, descriptive

## Scope

This toolkit manages the *lifecycle* of security findings (track, SLA, report) and enforces pentest governance boundaries. Contributions that introduce exploit code, payload generators, or attack automation will not be accepted.
