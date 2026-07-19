# Agent Workflow

This repository is the data-processing workspace for audit-derived training data. Keep raw data and local secrets out of Git.

## Worktree Policy

- Keep the main checkout on `main` for integration only.
- Do not develop by switching the main checkout to task branches.
- For each change, create an isolated worktree under `.worktrees/<task-slug>`.
- Use a temporary branch for the worktree when Git requires one, preferably `codex/<task-slug>`.
- Treat task branches as disposable: after the work is merged into `main`, remove the worktree and delete the local and remote temporary branch.
- Push a task branch only when saving progress, sharing review state, or preserving work before a break.

Suggested flow:

```bash
git checkout main
git pull --ff-only origin main
git worktree add .worktrees/<task-slug> -b codex/<task-slug> main
cd .worktrees/<task-slug>
```

After verification:

```bash
cd /ai_paas_jf/sunlg/data
git checkout main
git pull --ff-only origin main
git merge --ff-only codex/<task-slug>
git push origin main
git worktree remove .worktrees/<task-slug>
git worktree prune
git branch -d codex/<task-slug>
git push origin --delete codex/<task-slug>
```

## Data Safety

- Never commit `.env`, generated outputs, raw audit files, or synthetic sample output directories.
- Real audit data lives outside this repo under `/isos_data_share/audit`; read it only through the sanitizing pipeline.
- Do not send raw audit records, raw prompts, user identifiers, tenant identifiers, request IDs, file paths, API keys, IPs, or session identifiers to external models.
- External model calls for sample generation must be synthetic-only unless a future written design explicitly approves a safer alternative.
- Keep provider keys in local `.env` files. Use `.env.example` only for placeholder variable names.

## Verification

Before merging or reporting success, run the relevant checks from inside the task worktree:

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
git diff --check
```

For the synthetic generator, also run a small safe smoke test when credentials are available:

```bash
scripts/run_synthetic_samples.sh --target-count 1 --batch-size 1
```

Confirm that `.env` and `audit_training/synthetic_samples/` remain ignored before staging.
