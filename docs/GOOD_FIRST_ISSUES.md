# Good first issues

These starter specifications are intentionally narrow. Each should include regression tests and must not weaken the security invariants in `CONTRIBUTING.md`.

1. **Expand GNU tar fixture coverage.** Add static audit fixtures for additional documented helper-command spellings, with benign abbreviated-option controls that must remain clean.

2. **Add more PowerShell normalization fixtures.** Cover additional Unicode dash code points and abbreviation boundaries. Tests must verify that ordinary positional text after a real end-of-options-aware tool is not affected.

3. **Document basename versus absolute allowlisting.** Add a short docs page with threat-model diagrams in text form and examples showing why absolute paths are preferred.

4. **Add a CLI golden-file test suite.** Store deterministic JSON audit outputs for benign and dangerous fixtures, then compare stable keys rather than full volatile output.

5. **Improve type annotations.** Audit public signatures with a type checker in strict mode while preserving Python 3.9 compatibility and zero runtime dependencies.

6. **Add Windows CI smoke coverage.** Propose a separate Windows workflow that validates batch extension, trailing-dot, ADS spelling, drive-path, and `SYSTEMROOT` behavior without executing batch files.

7. **Measure timeout precision.** Add a performance regression test that bounds watchdog overhead without making the test flaky on shared CI runners.

8. **Write an MCP integration example.** Create a small documented example server shape that exposes one narrow tool and never exposes a general-purpose shell tool.

9. **Audit documentation claims against tests.** Write a test inventory that maps every README guarantee to at least one test file and identifies any unverified claim.

10. **Add environment key fuzz fixtures.** Generate deterministic printable and non-printable key-shape cases, verifying that invalid key text is never leaked into findings.
