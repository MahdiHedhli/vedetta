#!/bin/bash
# deploy.sh — Push from this machine, then update Core on Mac Studio
# Usage: ./scripts/deploy.sh [commit message]
#
# Prerequisites:
#   - SSH key access to Mac Studio (ssh-copy-id macstudio)
#   - MAC_STUDIO_HOST env var or edit the default below

set -euo pipefail

MAC_STUDIO_HOST="${MAC_STUDIO_HOST:-macstudio.local}"
VEDETTA_DIR="$HOME/Documents/Coding/Vedetta"
REMOTE_DIR="$HOME/Documents/Coding/Vedetta"

cd "$VEDETTA_DIR"

# --- Step 1: Commit & Push ---
echo "==> Checking for changes..."
if [[ -n $(git status --porcelain) ]]; then
    git add -A
    if [[ -n "${1:-}" ]]; then
        git commit -m "$1"
    else
        echo "Uncommitted changes found but no commit message provided."
        echo "Usage: ./scripts/deploy.sh \"your commit message\""
        exit 1
    fi
fi

echo "==> Pushing to origin..."
git push

# --- Step 2: Update Mac Studio ---
echo "==> Updating Mac Studio ($MAC_STUDIO_HOST)..."
ssh "$MAC_STUDIO_HOST" "cd $REMOTE_DIR && git pull && ./scripts/update-all.sh"

echo "==> Deploy complete."
