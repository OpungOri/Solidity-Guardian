# Architecture

## Design goals

1. Audit-first default
   The tool should produce findings and diagnostics unless the operator explicitly requests PoC generation.

2. Deterministic source mapping
   `src` fields follow the Solidity compiler format `start:length:sourceIndex`. The mapper resolves the source file from `sourceIndex` and computes line numbers from explicit `line_starts` data, avoiding ad hoc logic.

3. Conservative scoring
   Scoring should be deterministic and testable. The system prefers fewer, better-evidenced findings over noisy heuristics.

4. Security hardening of the tool itself
   Compiler invocations must be bounded, environment-minimized, and fail gracefully. Inputs must be validated and scoped to project roots.

## Main components

- `wizard_audit/cli.py`
  CLI entry point and argument validation.

- `wizard_audit/config.py`
  Loads configuration with precedence: CLI > environment > YAML defaults.

- `wizard_audit/compiler.py`
  Runs the compiler with sanitized environment and bounded execution.

- `wizard_audit/source_mapper.py`
  Resolves AST offsets to concrete source lines and metadata.

- `wizard_audit/orchestrator.py`
  Coordinates the analysis workflow and preserves default audit/report-only mode.

- `wizard_audit/exporter.py`
  Serializes findings and diagnostics into stable JSON output.

- `wizard_audit/diagnostics.py`
  Structured event sink with correlation IDs and JSON serialization.

## Operational model

The tool is intentionally conservative:
- It does not auto-execute PoC files.
- Findings are separate from candidate exploit templates.
- Audit results remain the primary artifact by default.

## Constraints and boundaries

- Not a symbolic executor
- Not a full exploit viability engine
- External tools remain optional evidence only
- False-positive reduction is prioritized over “finding volume”
