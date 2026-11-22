#!/usr/bin/env bash
# Sample the Python process and its direct FFmpeg children once per second.
set -u

if [ "$#" -ne 2 ]; then
    echo "usage: $0 APP_PID OUTPUT.csv" >&2
    exit 2
fi

app_pid=$1
output=$2
if ! [[ $app_pid =~ ^[0-9]+$ ]] || ! kill -0 "$app_pid" 2>/dev/null; then
    echo "APP_PID must be a running process ID" >&2
    exit 2
fi

printf 'unix_time,role,pid,cpu_percent,rss_kib,command\n' > "$output"
while kill -0 "$app_pid" 2>/dev/null; do
    stamp=$(date +%s)
    ps -p "$app_pid" -o pid=,pcpu=,rss=,comm= 2>/dev/null |
        awk -v stamp="$stamp" '{printf "%s,python,%s,%s,%s,%s\n", stamp, $1, $2, $3, $4}' >> "$output"
    ps --ppid "$app_pid" -o pid=,pcpu=,rss=,comm= 2>/dev/null |
        awk -v stamp="$stamp" '{printf "%s,child,%s,%s,%s,%s\n", stamp, $1, $2, $3, $4}' >> "$output"
    sleep 1
done
