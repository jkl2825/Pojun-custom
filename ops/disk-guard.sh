#!/usr/bin/env bash
# Check both the container filesystem and the mounted data filesystem.
# Never remove test directories or traffic rollback journals from outside Pojun.
# Credentials for optional emergency pause come from environment/.env:
# POJUN_GUARD_USERNAME and POJUN_GUARD_PASSWORD (no credentials in this script).
set -uo pipefail

CONTAINER="${POJUN_CONTAINER:-pojun-pojun-1}"
DB_CONTAINER="${POJUN_DB_CONTAINER:-pojun-postgres-1}"
API="${POJUN_API:-http://localhost:8887}"
WARN_PCT="${WARN_PCT:-85}"
CRIT_PCT="${CRIT_PCT:-92}"
EMERG_PCT="${EMERG_PCT:-96}"
TASK_MAX_MB="${TASK_MAX_MB:-2048}"
LOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$LOG_DIR/disk-guard.log"
AUTO_PAUSE=0
QUIET=0
for a in "$@"; do
  case "$a" in
    --auto-pause) AUTO_PAUSE=1 ;;
    --quiet) QUIET=1 ;;
    *) echo "Unknown argument: $a" >&2; exit 1 ;;
  esac
done
say() { [ "$QUIET" -eq 1 ] && return 0; echo "$@"; }
log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$LOG_FILE"; }
alert() { echo "$@" | tee -a "$LOG_FILE" >&2; }
export MSYS_NO_PATHCONV=1

for value in "$WARN_PCT" "$CRIT_PCT" "$EMERG_PCT" "$TASK_MAX_MB"; do
  [[ "$value" =~ ^[0-9]+$ ]] || { alert "[disk-guard] Invalid numeric threshold"; exit 1; }
done
if ! (( WARN_PCT < CRIT_PCT && CRIT_PCT < EMERG_PCT && EMERG_PCT <= 100 )); then
  alert "[disk-guard] Require WARN < CRIT < EMERG <= 100"
  exit 1
fi
if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" != "true" ]; then
  alert "[disk-guard] Container unavailable: $CONTAINER"
  exit 1
fi

# /app/data can be a Windows bind mount with an entirely different free-space pool.
# Use the final df row rather than a field from the Windows filesystem name.
PCT=0
WATERMARKS=""
for mount in / /app/data; do
  pct=$(docker exec "$CONTAINER" df -P "$mount" 2>/dev/null | awk 'NR>1 {p=$(NF-1)} END {gsub(/%/,"",p); print p}' | tr -d '\r')
  if ! [[ "$pct" =~ ^[0-9]+$ ]] || [ "$pct" -gt 100 ]; then
    alert "[disk-guard] Cannot read filesystem watermark: $mount"
    exit 1
  fi
  WATERMARKS="$WATERMARKS $mount=${pct}%"
  [ "$pct" -le "$PCT" ] || PCT=$pct
done
say "[disk-guard] Filesystems:$WATERMARKS"
size_of() { docker exec "$CONTAINER" du -sm "$1" 2>/dev/null | cut -f1 | tr -d '\r'; }
D_DATA=$(size_of /app/data); D_DATA=${D_DATA:-0}
D_TMP=$(size_of /tmp); D_TMP=${D_TMP:-0}
D_TRAFFIC=$(size_of /app/data/traffic); D_TRAFFIC=${D_TRAFFIC:-0}
say "[disk-guard] data=${D_DATA}M tmp=${D_TMP}M traffic=${D_TRAFFIC}M"
BIG_TASKS=$(docker exec "$CONTAINER" sh -c '
  for d in /app/data/tasks/*/; do
    [ -d "$d" ] || continue
    m=$(du -sm "$d" 2>/dev/null | cut -f1)
    [ -z "$m" ] || [ "$m" -le "$1" ] || printf "%s %s\n" "$m" "$(basename "$d")"
  done' sh "$TASK_MAX_MB" 2>/dev/null | sort -rn)
if [ -n "$BIG_TASKS" ]; then
  alert "[disk-guard] Task directories exceed ${TASK_MAX_MB}MB:"
  while read -r mb task; do alert "    task $task = ${mb}MB"; done <<<"$BIG_TASKS"
fi

RC=0
if [ "$PCT" -ge "$EMERG_PCT" ]; then
  RC=3
elif [ "$PCT" -ge "$CRIT_PCT" ]; then
  RC=2
elif [ "$PCT" -ge "$WARN_PCT" ]; then
  RC=1
fi
if [ "$RC" -gt 0 ]; then
  alert "[disk-guard] ALERT level=$RC filesystems:$WATERMARKS"
fi
if [ "$RC" -ge 2 ]; then
  STG=$(size_of /app/data/traffic/_delete_staging); STG=${STG:-0}
  alert "[disk-guard] No automatic deletion: rollback staging=${STG}MB; use application-owned committed GC."
fi

if [ "$RC" -ge 3 ] && [ "$AUTO_PAUSE" -eq 1 ]; then
  # Read only these two keys; never source/eval an arbitrary .env file.
  if [ -f "$LOG_DIR/../.env" ]; then
    while IFS='=' read -r key value || [ -n "$key" ]; do
      value=${value%$'\r'}
      case "$value" in \"*\") value=${value:1:${#value}-2} ;; \'*\') value=${value:1:${#value}-2} ;; esac
      case "$key" in
        POJUN_GUARD_USERNAME) POJUN_GUARD_USERNAME=${POJUN_GUARD_USERNAME:-$value} ;;
        POJUN_GUARD_PASSWORD) POJUN_GUARD_PASSWORD=${POJUN_GUARD_PASSWORD:-$value} ;;
      esac
    done < "$LOG_DIR/../.env"
  fi
  if [ -z "${POJUN_GUARD_USERNAME:-}" ] || [ -z "${POJUN_GUARD_PASSWORD:-}" ]; then
    alert "[disk-guard] Emergency pause unavailable: configure POJUN_GUARD_USERNAME/POJUN_GUARD_PASSWORD."
    exit 3
  fi
  AUTH_JSON=$(docker exec -e "POJUN_GUARD_USERNAME=$POJUN_GUARD_USERNAME" -e "POJUN_GUARD_PASSWORD=$POJUN_GUARD_PASSWORD" "$CONTAINER" python3 -c 'import json,os; print(json.dumps({"username":os.environ["POJUN_GUARD_USERNAME"],"password":os.environ["POJUN_GUARD_PASSWORD"]}))')
  if LOGIN=$(curl --fail --silent --show-error --max-time 10 -X POST "$API/api/auth/login" -H "Content-Type: application/json" --data-binary "$AUTH_JSON" 2>/dev/null); then
    TOK=$(printf '%s' "$LOGIN" | docker exec -i "$CONTAINER" python3 -c 'import json,sys; d=json.load(sys.stdin); t=d.get("token"); print(t if isinstance(t,str) else "")' 2>/dev/null)
  else
    TOK=""
  fi
  unset AUTH_JSON LOGIN POJUN_GUARD_PASSWORD
  if [ -z "$TOK" ]; then
    alert "[disk-guard] Login failed; no task was paused."
    exit 3
  fi
  if ! IDS=$(docker exec "$DB_CONTAINER" psql -X -v ON_ERROR_STOP=1 -U pojun -d pojun -tAc "SELECT id FROM tasks WHERE status='running' AND deleted_at IS NULL ORDER BY id" 2>/dev/null | tr -d '\r'); then
    alert "[disk-guard] Failed to list running tasks."
    exit 3
  fi
  for id in $IDS; do
    [[ "$id" =~ ^[0-9]+$ ]] || continue
    if BODY=$(curl --fail --silent --show-error --max-time 20 -X POST "$API/api/tasks/$id/control" -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" -d '{"action":"pause"}' 2>/dev/null) &&
       printf '%s' "$BODY" | docker exec -i "$CONTAINER" python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("paused") is True else 1)' 2>/dev/null; then
      alert "[disk-guard] Paused task $id (HTTP success and paused=true confirmed)"
    else
      alert "[disk-guard] Failed to confirm pause for task $id"
    fi
  done
  unset TOK BODY
fi
log "level=$RC filesystems:$WATERMARKS data=${D_DATA}M tmp=${D_TMP}M traffic=${D_TRAFFIC}M"
exit "$RC"
