# Solidity Guardian

Solidity Guardian is an audit-first Solidity security analysis tool. It emphasizes evidence, deterministic scoring, and conservative findings over speculative exploit generation.

Default mode
- `solidity-guardian -f Contract.sol` performs audit/report work only.
- It emits structured findings and diagnostics.
- PoC generation is opt-in and requires `--generate-poc`.

Core principles
- Evidence over volume
- Traceable findings over speculative findings
- Deterministic source mapping over ad hoc line guessing
- Audit-first default over automatic exploit generation
- Safe bounded execution for compiler and external tools

Quick start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
solidity-guardian -f examples/Token.sol --output out/
```

Explicit PoC mode
```bash
solidity-guardian -f examples/Token.sol --generate-poc --output out/
```

Key modules
- `wizard_audit/source_mapper.py`: deterministic AST-to-source mapping
- `wizard_audit/config.py`: YAML/env/CLI precedence
- `wizard_audit/compiler.py`: bounded compiler execution
- `wizard_audit/orchestrator.py`: audit workflow orchestration
- `wizard_audit/exporter.py`: stable JSON report outputs
- `wizard_audit/diagnostics.py`: structured logging and correlation IDs

Limitations
- This is static-analysis-first, not symbolic execution.
- It does not infer end-to-end exploit viability in arbitrary runtime states.
- External tools are optional evidence, not ground truth.
- False-positive reduction is preferred over maximizing finding volume.

Legal / safety notice
This tool is intended for authorized security research, internal code review, and defensive security work in environments where the operator has explicit permission to analyze the codebase.
