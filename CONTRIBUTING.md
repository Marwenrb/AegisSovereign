# Contributing to AegisSovereign

**Lead Architect & Developer:** [Marouan Rabai](https://marwenrabai.com)
**Maintained by:** [Cristi Labs](https://cristilabs.net)
**Normative Reference:** `AEGIS-SOVEREIGN-2026`

---

Thank you for contributing to AegisSovereign, the sovereign-grade 9-plane anti-automation and fraud defense engine.

---

## Code Contribution Standards

1. **Strict Typing:** All new code must be fully annotated and pass `mypy --strict`.
2. **Zero Core Dependencies:** Core runtime logic must not introduce third-party package dependencies. Leverage Python 3.10–3.13 standard libraries (`dataclasses`, `hashlib`, `hmac`, `secrets`, `threading`, `collections`, `ipaddress`).
3. **Sub-Millisecond Budget:** Evaluation pathways must maintain sub-millisecond P99 latency (`< 0.5 ms` typical). Run `aegis-sovereign benchmark` to verify.
4. **Attacker-Cost Asymmetry:** Security-sensitive changes must prove that defensive compute cost remains negligible while attacker compute scales exponentially.
5. **No Absolute Paths:** Code, documentation, and tests must remain fully portable and must never contain local machine file paths or credentials.

---

## Development Workflow

1. Fork the repository and create a feature branch (`feat/<plane>-<short-description>`).
2. Implement your changes following the architectural principles outlined in [`docs/02-ARCHITECTURE-9-PLANES.md`](docs/02-ARCHITECTURE-9-PLANES.md).
3. If new environment settings are introduced, document them in `.env.example`, [`docs/05-CLI-AND-OPERATIONS.md`](docs/05-CLI-AND-OPERATIONS.md), and wire them into `SecurityConfig.from_environment()`.
4. Run the full verification suite before committing:
   ```bash
   # Run all 42 automated tests
   make test
   # OR: python -m unittest discover tests -v

   # Run verification contracts
   make verify
   # OR: python verify_imports.py && python verify_config.py && python verify_unified.py

   # Verify system doctor
   make doctor
   ```
5. Open a Pull Request against `main`. All PRs undergo automated multi-OS matrix testing via GitHub Actions.
