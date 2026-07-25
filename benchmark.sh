#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_PATH="$ROOT_DIR/_bin/behind"
CONF_PATH="${CONF_PATH:-$ROOT_DIR/scripts/behind.conf}"
QUERYFILE="${QUERYFILE:-/home/soramimi/dnsperf/query.txt}"
SERVER_ADDR="${SERVER_ADDR:-127.0.0.1}"
SERVER_PORT="${SERVER_PORT:-5301}"
STARTUP_WAIT_SECS="${STARTUP_WAIT_SECS:-5}"

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

read_config_number() {
	local key="$1"
	local default_value="$2"
	local value
	value="$(awk -F= -v wanted="$key" '
		/^[[:space:]]*[;#]/ { next }
		{
			left = $1
			gsub(/[[:space:]]/, "", left)
			if (left != wanted) next
			right = $2
			gsub(/[[:space:]]/, "", right)
			if (right ~ /^[0-9]+$/) value = right
		}
		END {
			if (value != "") {
				print value
			}
		}
	' "$CONF_PATH")"
	if [[ -n "$value" ]]; then
		printf '%s\n' "$value"
	else
		printf '%s\n' "$default_value"
	fi
}

wait_for_server() {
	local pid="$1"
	local deadline=$((SECONDS + STARTUP_WAIT_SECS))
	while (( SECONDS < deadline )); do
		if ! kill -0 "$pid" 2>/dev/null; then
			echo "behind exited before it became ready" >&2
			return 1
		fi
		if command -v dig >/dev/null 2>&1; then
			if dig @"$SERVER_ADDR" -p "$SERVER_PORT" . NS +time=1 +tries=1 >/dev/null 2>&1; then
				return 0
			fi
		else
			sleep 1
			return 0
		fi
		sleep 0.1
	done
	echo "timeout waiting for behind to accept queries" >&2
	return 1
}

cleanup() {
	local rc=$?
	if [[ -n "${PID_BEHIND:-}" ]] && kill -0 "$PID_BEHIND" 2>/dev/null; then
		kill "$PID_BEHIND" 2>/dev/null || true
		wait "$PID_BEHIND" 2>/dev/null || true
	fi
	if [[ -n "${LOG_FILE:-}" && -f "${LOG_FILE:-}" ]]; then
		rm -f "$LOG_FILE"
	fi
	exit "$rc"
}

require_command make
require_command resperf

if [[ -n "${QUERYFILE:-}" && ! -f "$QUERYFILE" ]]; then
	echo "query file not found: $QUERYFILE" >&2
	exit 1
fi
if [[ ! -f "$CONF_PATH" ]]; then
	echo "configuration file not found: $CONF_PATH" >&2
	exit 1
fi

trap cleanup EXIT INT TERM

MAX_TASKS="$(read_config_number max-tasks 500)"
RESPERF_TIMEOUT="${RESPERF_TIMEOUT:-45}"
RESPERF_MAX_QPS="${RESPERF_MAX_QPS:-100000}"
RESPERF_RAMP_TIME="${RESPERF_RAMP_TIME:-5}"
RESPERF_CONSTANT_TIME="${RESPERF_CONSTANT_TIME:-20}"
RESPERF_CLIENTS="${RESPERF_CLIENTS:-1}"
RESPERF_MAX_LOSS="${RESPERF_MAX_LOSS:-100}"
RESPERF_FALL_BEHIND="${RESPERF_FALL_BEHIND:-0}"
RESPERF_OUTSTANDING="${RESPERF_OUTSTANDING:-$((MAX_TASKS * 8))}"

if (( RESPERF_OUTSTANDING < 1024 )); then
	RESPERF_OUTSTANDING=1024
fi

make -j2
"$BIN_PATH" --check-config -C "$CONF_PATH"

LOG_FILE="$(mktemp /tmp/behind-benchmark.XXXXXX.log)"
"$BIN_PATH" -C "$CONF_PATH" --log-file "$LOG_FILE" &
PID_BEHIND=$!

wait_for_server "$PID_BEHIND"

RESPERF_CMD=(
	resperf
	-s "$SERVER_ADDR"
	-p "$SERVER_PORT"
	-d "$QUERYFILE"
	-t "$RESPERF_TIMEOUT"
	-m "$RESPERF_MAX_QPS"
	-r "$RESPERF_RAMP_TIME"
	-c "$RESPERF_CONSTANT_TIME"
	-L "$RESPERF_MAX_LOSS"
	-C "$RESPERF_CLIENTS"
	-q "$RESPERF_OUTSTANDING"
	-F "$RESPERF_FALL_BEHIND"
)

echo "Benchmark configuration:"
echo "  config:        $CONF_PATH"
echo "  queryfile:     $QUERYFILE"
echo "  server:        $SERVER_ADDR:$SERVER_PORT"
echo "  max-tasks:     $MAX_TASKS"
echo "  outstanding:   $RESPERF_OUTSTANDING"
echo "  max-qps:       $RESPERF_MAX_QPS"
echo "  ramp-time:     $RESPERF_RAMP_TIME"
echo "  constant-time: $RESPERF_CONSTANT_TIME"
echo "  timeout:       $RESPERF_TIMEOUT"
echo
printf 'Running:'
printf ' %q' "${RESPERF_CMD[@]}"
printf '\n\n'

"${RESPERF_CMD[@]}"
