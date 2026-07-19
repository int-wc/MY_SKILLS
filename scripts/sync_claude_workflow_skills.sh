#!/usr/bin/env bash
set -euo pipefail

SRC_ROOT="${CLAUDE_SKILLS_SRC:-$HOME/.claude/skills}"
DST_ROOT="${MY_SKILLS_BACKUP:-$HOME/backup/MY_SKILLS}"
REMOTE="${MY_SKILLS_GIT_REMOTE:-origin}"
BRANCH="${MY_SKILLS_GIT_BRANCH:-master}"
PUSH="${MY_SKILLS_GIT_PUSH:-1}"

if [[ ! -d "$SRC_ROOT" ]]; then
  echo "source skills directory not found: $SRC_ROOT" >&2
  exit 1
fi

if [[ ! -d "$DST_ROOT/.git" ]]; then
  echo "backup directory is not a git repository: $DST_ROOT" >&2
  exit 1
fi

lock_file="$DST_ROOT/.sync_claude_workflow_skills.lock"
exec 9>"$lock_file"
if ! flock -n 9; then
  echo "sync already running; skip"
  exit 0
fi

mapfile -t skill_dirs < <(find "$SRC_ROOT" -mindepth 2 -maxdepth 2 -name workflow_runner.js -printf '%h\n' | sort)

if [[ "${#skill_dirs[@]}" -eq 0 ]]; then
  echo "no workflow_runner.js skills found under $SRC_ROOT"
  exit 0
fi

synced=()
for skill_dir in "${skill_dirs[@]}"; do
  skill_name="$(basename "$skill_dir")"
  mkdir -p "$DST_ROOT/$skill_name"
  rsync -a --delete \
    --exclude '.git/' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    --exclude '.DS_Store' \
    "$skill_dir/" "$DST_ROOT/$skill_name/"
  synced+=("$skill_name")
done

cd "$DST_ROOT"

git add -- "${synced[@]}" scripts

if git diff --cached --quiet; then
  echo "no skill changes to commit"
  exit 0
fi

summary="$(printf '%s ' "${synced[@]}")"
git commit -m "sync claude workflow skills: ${summary% }"

if [[ "$PUSH" == "1" ]]; then
  git push "$REMOTE" "$BRANCH"
fi

