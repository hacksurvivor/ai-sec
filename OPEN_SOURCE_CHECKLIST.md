# Open Source Release Checklist

Use this checklist before each public tag/release.

## 1) Repository hygiene

- [ ] `git status` is clean (or intentional changes only).
- [ ] No secrets in tracked files.
- [ ] No absolute local paths in tracked files.
- [ ] No personal identifiers you do not want public (emails, usernames, machine names).
- [ ] `tmp/`, generated files, and local notes are ignored or removed.

Recommended quick scan:

```bash
rg -n --hidden --glob '!.git' --glob '!node_modules' \
  '(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|xox[baprs]-|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})'
rg -n --hidden --glob '!.git' --glob '!node_modules' '/Users/'
```

## 2) Build and quality gates

- [ ] Install dependencies from lockfile.
- [ ] Build all workspaces.
- [ ] Run lint.
- [ ] Run gateway tests.
- [ ] Run CLI tests.
- [ ] Run red-team suite.

Command:

```bash
npm ci
npm run release:verify
```

## 3) Release artifact checks

- [ ] Build tarball(s) and checksums.
- [ ] Inspect tarball contents to confirm only intended files are shipped.
- [ ] Verify no source maps or debug-only files are published (unless intentional).

Commands:

```bash
npm run release:cli:pack
npm run release:cli:checksums
tar -tzf release/ai-sec-cli-*.tgz
```

## 4) Tag and publish

- [ ] Tag with semantic version (`vX.Y.Z`).
- [ ] Push `main` and tag.
- [ ] Confirm GitHub Actions release workflow succeeds.
- [ ] Confirm release assets include tarball + `checksums.txt`.

## 5) Post-release verification

- [ ] Install released tarball in a clean shell and run `ai-sec`.
- [ ] Confirm README install instructions match released artifact names.
- [ ] Confirm `SECURITY.md` and reporting path are still correct.
