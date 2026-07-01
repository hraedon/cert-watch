#!/usr/bin/env bash
# Update Playwright visual-regression baselines from the CI artifact.
#
# Usage:
#   ./scripts/update-visual-baselines.sh <run-url|run-id>
#   ./scripts/update-visual-baselines.sh --latest
#   ./scripts/update-visual-baselines.sh --latest --dry-run
set -euo pipefail

DRY_RUN=0
RUN_ARG=""

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        *) RUN_ARG="$arg" ;;
    esac
done

die() { echo "update-visual-baselines: $*" >&2; exit 1; }

if ! command -v gh >/dev/null 2>&1; then
    die "gh CLI is required (https://cli.github.com)"
fi

if ! gh auth status >/dev/null 2>&1; then
    die "gh is not authenticated; run 'gh auth login'"
fi

if ! gh repo view --json nameWithOwner >/dev/null 2>&1; then
    die "not inside a GitHub repository"
fi

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || die "not in a git repo"
BASELINE_DIR="$ROOT/tests/e2e/__screenshots__"
if [ ! -d "$BASELINE_DIR" ]; then
    die "baseline directory not found: $BASELINE_DIR"
fi

extract_run_id() {
    local input="$1"
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        echo "$input"
    elif [[ "$input" =~ /runs/([0-9]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        die "cannot extract run id from: $input"
    fi
}

find_latest_failed_visual_run() {
    local runs run_id visual_failed
    runs="$(gh run list --workflow=e2e --status=failure --limit 20 --json databaseId,url --jq '.[].databaseId')" || return 1
    for run_id in $runs; do
        visual_failed="$(gh run view "$run_id" --json jobs --jq '.jobs[] | select(.name == "visual" and .conclusion == "failure")' 2>/dev/null)"
        if [ -n "$visual_failed" ]; then
            echo "$run_id"
            return 0
        fi
    done
    return 1
}

resolve_run_id() {
    if [ -z "$RUN_ARG" ] || [ "$RUN_ARG" = "--latest" ]; then
        local latest
        latest="$(find_latest_failed_visual_run)" || die "no failed visual job found in recent e2e runs"
        echo "$latest"
    else
        extract_run_id "$RUN_ARG"
    fi
}

RUN_ID="$(resolve_run_id)"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ARTIFACT_DIR="$TMP_DIR/artifact"
mkdir -p "$ARTIFACT_DIR"

echo "Downloading visual-snapshot-diffs from run $RUN_ID ..."
if ! gh run download "$RUN_ID" --name visual-snapshot-diffs --dir "$ARTIFACT_DIR" >/dev/null 2>&1; then
    die "artifact 'visual-snapshot-diffs' not found for run $RUN_ID"
fi

mapfile -t ACTUALS < <(find "$ARTIFACT_DIR" -type f -name 'actual_*.png')
if [ "${#ACTUALS[@]}" -eq 0 ]; then
    die "no actual_*.png files found in the downloaded artifact"
fi

MATCHED=0
MISSING=0
AMBIGUOUS=0

for actual in "${ACTUALS[@]}"; do
    name="$(basename "$actual")"
    base="${name#actual_}"

    mapfile -t targets < <(find "$BASELINE_DIR" -type f -name "$base")

    if [ "${#targets[@]}" -eq 0 ]; then
        echo "  SKIP: no baseline for $name"
        MISSING=$((MISSING + 1))
        continue
    fi

    if [ "${#targets[@]}" -gt 1 ]; then
        echo "  SKIP: ambiguous baseline for $name"
        for t in "${targets[@]}"; do echo "        $t"; done
        AMBIGUOUS=$((AMBIGUOUS + 1))
        continue
    fi

    target="${targets[0]}"
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "  DRY-RUN: would update $target from $name"
    else
        cp "$actual" "$target"
        echo "  UPDATED: $target"
    fi
    MATCHED=$((MATCHED + 1))
done

echo ""
echo "Summary:"
echo "  run id:    $RUN_ID"
echo "  matched:   $MATCHED"
echo "  missing:   $MISSING"
echo "  ambiguous: $AMBIGUOUS"

if [ "$DRY_RUN" -eq 1 ]; then
    echo "  (dry run: no files were changed)"
fi
