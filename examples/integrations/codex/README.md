# Codex Integration

Codex currently supports config/MCP and non-interactive execution (`codex exec`), but not a dedicated pre-tool hook key in `config.toml`.

This integration provides a guarded wrapper for agent workflows.

## Install

```bash
bash ./examples/integrations/codex/install.sh
```

## Use

```bash
codex-ai-sec --prompt "Summarize this repo safely" --tool terminal.exec
```

Stdin mode:

```bash
echo "Refactor this module" | codex-ai-sec --stdin --tool terminal.exec --tool write_file
```

If gate passes, wrapper runs `codex exec ...`. If gate fails, it exits with ai-sec exit code.
