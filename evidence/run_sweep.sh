#!/usr/bin/env bash
# Staged search runner for the Genesis block wallet puzzle.
#
# Runs each stage as a separate engine invocation so a crash or a restart
# loses at most one stage, and appends a one-line result per stage to a log.
# Nothing here spends, signs, or broadcasts.
#
# Usage:  bash run_sweep.sh <logfile> [stage ...]
#         bash run_sweep.sh /tmp/sweep.log            # run all stages
#         bash run_sweep.sh /tmp/sweep.log fullhex    # run one stage

set -u
cd "$(dirname "$0")"
PY=/app/.venv/bin/python
LOG=${1:-/tmp/sweep.log}
shift || true

ALL_STAGES=(jqfull jqfull_indep semantic fullhex fullhex_indep)

# stage name -> solver arguments
stage_args() {
  case "$1" in
    # getblock JSON fields, whole-value only, every derived account candidate
    jqfull)
      echo "--fields jq --digest-mode whole --accounts all --leaves all" ;;
    # same, but the two-cosigner / two-seed model
    jqfull_indep)
      echo "--fields jq --digest-mode whole --accounts all --leaves all --indep" ;;
    # tool-plausible sub-ranges of every rendered field, pruned accounts
    semantic)
      echo "--fields raw_block:hex,raw_header:hex,raw_tx:hex,raw_scriptsig:hex,raw_block:raw,raw_header:raw,raw_tx:raw,raw_scriptsig:raw,coinbase_text:txt,headline:txt,merkle:hex,nonce:hex,time:hex,bits:hex,block_hash:hex,coinbase_pubkey:hex,pubkey_x:hex,pubkey_y:hex --digest-mode semantic --accounts prune --leaves all" ;;
    # every contiguous character range of the 570-char bitcoin-cli getblock output
    fullhex)
      echo "--fields raw_block:hex --digest-mode full --account-only 0,1,2,2009,2083236893,1231006505,486604799 --leaves std" ;;
    fullhex_indep)
      echo "--fields raw_block:hex --digest-mode full --account-only 0,1,2,2009,2083236893,1231006505,486604799 --leaves std --indep" ;;
    *) return 1 ;;
  esac
}

STAGES=("$@")
if [ ${#STAGES[@]} -eq 0 ]; then
  STAGES=("${ALL_STAGES[@]}")
fi

for stage in "${STAGES[@]}"; do
  args=$(stage_args "$stage") || { echo "unknown stage: $stage" >&2; exit 2; }
  echo "=== $stage $(date -u +%FT%TZ) :: $args" >> "$LOG"
  start=$(date +%s)
  # shellcheck disable=SC2086
  $PY solve.py $args >> "$LOG" 2>&1
  rc=$?
  end=$(date +%s)
  echo "--- $stage rc=$rc elapsed=$((end - start))s" >> "$LOG"
done
echo "ALL STAGES DONE $(date -u +%FT%TZ)" >> "$LOG"
