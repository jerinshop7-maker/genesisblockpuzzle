#!/usr/bin/env bash
# Staged, checkpointed search runner for the Genesis block wallet puzzle.
#
# Two things this fixes over a plain "run one big job" loop:
#
#   1. CHUNKING. Long axes are split into chunks that finish in minutes, and each
#      chunk is recorded in a checkpoint file before the next one starts. A crash
#      or a host restart therefore costs at most one chunk, and re-running the
#      script resumes instead of restarting.
#   2. PROGRESS. The engine prints a heartbeat every few seconds with the digest
#      index it has reached, so a run that dies is diagnosable rather than silent.
#
# Nothing here spends, signs, or broadcasts.
#
# Usage:  bash run_sweep.sh <logfile> [stage ...]
#         bash run_sweep.sh /tmp/sweep.log                     # all stages
#         bash run_sweep.sh /tmp/sweep.log fullhex             # one stage
#         RESUME=0 bash run_sweep.sh /tmp/sweep.log fullhex    # ignore checkpoints

set -u
cd "$(dirname "$0")"
PY=/app/.venv/bin/python
LOG=${1:-"$(pwd)/sweep.log"}
shift || true

ALL_STAGES=(coupled jqfull jqfull_indep semantic fullhex fullhex_indep)

# Arguments shared by every stage, minus the axes a stage varies.
BASE="--passphrases basic --leaves std"

# stage -> extra solver arguments. CHUNK is filled in per chunk when set.
stage_args() {
  case "$1" in
    jqfull)       echo "--fields jq --digest-mode whole --accounts all --leaves all" ;;
    jqfull_indep) echo "--fields jq --digest-mode whole --accounts all --leaves all --indep" ;;
    semantic)     echo "--fields raw_block:hex,raw_header:hex,raw_tx:hex,raw_scriptsig:hex,raw_block:raw,raw_header:raw,raw_tx:raw,raw_scriptsig:raw,coinbase_text:txt,headline:txt,merkle:hex,nonce:hex,time:hex,bits:hex,block_hash:hex,coinbase_pubkey:hex,pubkey_x:hex,pubkey_y:hex --digest-mode semantic --accounts prune --leaves all" ;;
    fullhex)      echo "--fields raw_block:hex --digest-mode full --account-only 0,1,2,2009,2083236893,1231006505,486604799 --leaves std" ;;
    fullhex_indep) echo "--fields raw_block:hex --digest-mode full --account-only 0,1,2,2009,2083236893,1231006505,486604799 --leaves std --indep" ;;
    *) return 1 ;;
  esac
}

# How many digest pieces each stage has in total, for chunking. Kept as a lookup
# so the runner does not have to enumerate 157k candidates just to slice them.
stage_total() {
  case "$1" in
    fullhex|fullhex_indep) echo 157207 ;;
    *) echo 0 ;;
  esac
}

CHUNK=${CHUNK:-20000}
# Checkpoints live next to the repo, not in /tmp: /tmp did not survive a host
# restart here, and a missing checkpoint file silently loses all progress.
CKPT=${CKPT:-"$(pwd)/sweep.ckpt"}
# Make sure the checkpoint file exists before anything tries to append to it.
: >> "$CKPT"
STAGES=("$@")
if [ ${#STAGES[@]} -eq 0 ]; then
  STAGES=("${ALL_STAGES[@]}")
fi

for stage in "${STAGES[@]}"; do
  # The coupled stage has its own driver: it pairs each Genesis field with only
  # the account number that field implies, so it must not go through solve.py.
  if [ "$stage" = "coupled" ]; then
    echo "=== $stage $(date -u +%FT%TZ) :: coupled_sweep.py" >> "$LOG"
    t0=$(date +%s)
    $PY coupled_sweep.py >> "$LOG" 2>&1
    rc=$?
    t1=$(date +%s)
    echo "--- $stage rc=$rc elapsed=$((t1 - t0))s" >> "$LOG"
    continue
  fi

  args=$(stage_args "$stage") || { echo "unknown stage: $stage" >&2; exit 2; }
  total=$(stage_total "$stage")

  if [ "$total" -gt 0 ] && [ "$CHUNK" -gt 0 ]; then
    echo "=== $stage $(date -u +%FT%TZ) chunked: $total pieces in chunks of $CHUNK" >> "$LOG"
    start=0
    while [ "$start" -lt "$total" ]; do
      if [ "${RESUME:-1}" = "1" ] && grep -qx "$stage $start done" "$CKPT" 2>/dev/null; then
        echo "--- $stage chunk@$start already done, skipping" >> "$LOG"
        start=$((start + CHUNK))
        continue
      fi
      echo "=== $stage chunk@$start $(date -u +%FT%TZ)" >> "$LOG"
      t0=$(date +%s)
      # shellcheck disable=SC2086
      $PY solve.py $args $BASE --chunk-start "$start" --chunk-size "$CHUNK" >> "$LOG" 2>&1
      rc=$?
      t1=$(date +%s)
      echo "$stage $start rc=$rc elapsed=$((t1 - t0))s" >> "$LOG"
      if [ $rc -eq 0 ]; then
        echo "MATCH IN STAGE $stage chunk@$start -- see $LOG" >> "$LOG"
        echo "$stage $start done" >> "$CKPT"
        exit 0
      fi
      # Only checkpoint completed chunks; rc!=0 with no output means it was
      # killed, so leave it unmarked and let the next run retry it.
      if [ $rc -eq 1 ]; then
        echo "$stage $start done" >> "$CKPT"
      fi
      start=$((start + CHUNK))
    done
  else
    echo "=== $stage $(date -u +%FT%TZ) :: $args" >> "$LOG"
    t0=$(date +%s)
    # shellcheck disable=SC2086
    $PY solve.py $args $BASE >> "$LOG" 2>&1
    rc=$?
    t1=$(date +%s)
    echo "--- $stage rc=$rc elapsed=$((t1 - t0))s" >> "$LOG"
    [ $rc -eq 0 ] && echo "MATCH IN STAGE $stage -- see $LOG" >> "$LOG"
  fi
done
echo "ALL STAGES DONE $(date -u +%FT%TZ)" >> "$LOG"