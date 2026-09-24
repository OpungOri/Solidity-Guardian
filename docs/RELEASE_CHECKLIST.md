# Release checklist

Use this checklist before tagging a release. Do not tag a production release until every required item is verified on a clean runner.

## Required automated gates

- [ ] `python -m pip install -e ".[dev]"` succeeds.
- [ ] `pytest -q` passes.
- [ ] `python -m compileall -q wizard_audit` passes.
- [ ] `python -m pip check` passes.
- [ ] A real `solc` compile succeeds for the vulnerable and safe corpus contracts.
- [ ] The CI workflow is enabled and green for the release commit.

## Behavioral gates

- [ ] Running the CLI without `--generate-poc` produces audit/report artifacts only.
- [ ] PoC generation is enabled only by an explicit opt-in flag.
- [ ] CLI values override environment values, and environment values override YAML defaults.
- [ ] Invalid paths, URLs, addresses, compiler versions, and negative fork blocks fail closed.
- [ ] Source locations are reproducible across repeated runs.
- [ ] JSON reports parse successfully and include a schema version and correlation ID.

## Security gates

- [ ] Input paths cannot escape the configured workspace root.
- [ ] External compiler execution has a timeout and a restricted environment.
- [ ] Secrets are not written to reports, diagnostics, or generated artifacts.
- [ ] No generated PoC is executed automatically.
- [ ] Dependency and license review is complete.
- [ ] The release was tested against both safe and vulnerable corpus examples.

## Release procedure

1. Run all required gates on a clean checkout.
2. Review the generated report and diagnostics artifacts manually.
3. Review the diff and confirm that no secrets or local paths are committed.
4. Update the project version and release notes.
5. Create an annotated tag only after CI is green.
6. Publish the release with the exact commit SHA and test results.

## Release status vocabulary

- **Development:** required gates are incomplete.
- **Release candidate:** implementation is complete, but live verification is pending.
- **Production release:** every required and security gate is green and reviewed.
