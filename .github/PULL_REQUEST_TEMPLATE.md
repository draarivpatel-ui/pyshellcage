## Summary

## Security invariants affected

- [ ] No runtime dependencies added
- [ ] Python 3.9 compatibility preserved
- [ ] No shell execution path added
- [ ] Executable allowlist remains mandatory
- [ ] Environment values are never printed
- [ ] Tests cover the change

## Test plan

- [ ] `PYTHONPATH=src python3 -m unittest discover -s tests`
- [ ] `python3 -m build`

## Notes for reviewers
