# Contributing

Thanks for contributing to RedTeam Agent!

## Security-sensitive project

This is a **dual-use security tool**. Guidelines:

1. **Playbooks (L0/開源)**: Safe probe logic + abstract DAG flows go in the open repo.
   Do **not** commit armed payloads (full credential-stuffing dictionaries, SSRF
   metadata payloads, specialized jailbreak libraries) to the public repo. These
   live in the L1 private submodule (requires signed use-declaration) or L2 local.
2. Review any payload you add for whether it could trash a system (no DROP/UPDATE,
   read-only + time-delay fuzz only).

## Setup

```bash
pip install -e .
```

## Development

- Python 3.11+
- Run lint: `ruff` on `src/redteam/`
- Run smoke test: `redteam --help` and `python -m pytest tests/`

## Pull request workflow

1. Fork & branch.
2. Add tests for new behavior.
3. Run `pytest`.
4. Open PR with a clear description.
5. Maintainers review for safety + license compliance (GPL tools only via subprocess).

## License

Apache 2.0. By contributing you agree your contributions are licensed accordingly.

## Code of conduct

Be respectful. This project deals with security tooling; keep discussion constructive.
