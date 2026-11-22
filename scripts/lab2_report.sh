#!/usr/bin/env bash
# Summarize final application logs, ps samples, and a receiver-side pcap.
set -euo pipefail

if [ "$#" -ne 5 ] && [ "$#" -ne 6 ]; then
    echo "usage: $0 SENDER.log RECEIVER.log SENDER.csv RECEIVER.csv RECEIVER.pcap [UDP_PORT]" >&2
    exit 2
fi

sender_log=$1
receiver_log=$2
sender_csv=$3
receiver_csv=$4
pcap=$5
port=${6:-5000}

for path in "$sender_log" "$receiver_log" "$sender_csv" "$receiver_csv" "$pcap"; do
    if [ ! -f "$path" ]; then
        echo "missing file: $path" >&2
        exit 2
    fi
done
command -v tshark >/dev/null || { echo 'tshark is required for pcap analysis' >&2; exit 2; }

field() {
    awk -v key="$2" '/ SESSION / {
        for (i = 1; i <= NF; i++) {
            if (index($i, key "=") == 1) {
                split($i, parts, "=")
                value = parts[2]
            }
        }
    } END { if (value == "") exit 2; print value }' "$1"
}

duration=$(field "$sender_log" duration_s)
formed=$(field "$sender_log" AU_total)
formed_bytes=$(field "$sender_log" H264_bytes_total)
sent_packets=$(field "$sender_log" UDP_sent)
send_failed=$(field "$sender_log" UDP_failed)
restored=$(field "$receiver_log" AU_complete)
restored_bytes=$(field "$receiver_log" H264_bytes)
received_packets=$(field "$receiver_log" UDP_received)
lost_estimate=$(field "$receiver_log" UDP_missing_estimate)
incomplete=$(field "$receiver_log" AU_incomplete)

awk -v t="$duration" -v formed="$formed" -v restored="$restored" \
    -v source_bytes="$formed_bytes" -v output_bytes="$restored_bytes" \
    -v sent="$sent_packets" -v failed="$send_failed" \
    -v received="$received_packets" -v lost="$lost_estimate" \
    -v incomplete="$incomplete" 'BEGIN {
        printf "Sender duration: %.3f s\n", t
        if (t < 300) print "Five-minute requirement: NOT MET"
        else print "Five-minute requirement: MET"
        printf "Formed frames: %d (%.2f fps)\n", formed, formed/t
        printf "Restored complete frames: %d (%.2f fps over sender duration)\n", restored, restored/t
        printf "Useful video speed: sender %.0f bit/s; receiver %.0f bit/s\n", source_bytes*8/t, output_bytes*8/t
        printf "UDP sent: %d; send errors: %d; received: %d; missing estimate: %d\n", sent, failed, received, lost
        printf "Incomplete access units: %d\n", incomplete
    }'

for csv in "$sender_csv" "$receiver_csv"; do
    printf '%s: ' "$csv"
    awk -F, 'NR > 1 {
        cpu[$1] += $4
        rss[$1] += $5
    } END {
        for (stamp in cpu) {
            count++
            total_cpu += cpu[stamp]
            if (rss[stamp] > max_rss) max_rss = rss[stamp]
        }
        if (count) printf "Process samples: %d; mean combined ps CPU: %.1f%%; peak combined RSS: %.0f KiB\n", count, total_cpu/count, max_rss
        else print "Process samples: 0"
    }' "$csv"
done

udp_count=$(tshark -r "$pcap" -Y "udp.dstport == $port" -T fields -e frame.number | awk 'END {print NR+0}')
if [ "$udp_count" -eq 0 ]; then
    echo "receiver pcap has no UDP packets for destination port $port" >&2
    exit 2
fi
fragment_count=$(tshark -r "$pcap" -Y 'ip.flags.mf == 1 || ip.frag_offset > 0' -T fields -e frame.number | awk 'END {print NR+0}')
max_ip_len=$(tshark -r "$pcap" -Y "udp.dstport == $port" -T fields -e ip.len | awk '$1 > max {max = $1} END {print max+0}')
printf 'Receiver pcap: UDP dst port %s packets=%s (includes control probes); IPv4 fragments=%s; max IPv4 length=%s bytes\n' \
    "$port" "$udp_count" "$fragment_count" "$max_ip_len"
