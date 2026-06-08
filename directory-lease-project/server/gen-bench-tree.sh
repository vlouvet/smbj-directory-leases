#!/bin/bash
# Generate a deep nested tree under testshare/benchtree on the host (fast, local fs).
# Both containers (new :1445, old :1446) see it via the same bind mount.
# Usage: gen-bench-tree.sh [DEPTH=3] [FANOUT=5] [FILES_PER_DIR=25]
set -euo pipefail
ROOT=/home/smbj/smbj-dirlease/testshare/benchtree
DEPTH=${1:-3}
FANOUT=${2:-5}
FPD=${3:-25}

rm -rf "$ROOT"
mkdir -p "$ROOT"

gen() {
    local dir=$1 depth=$2 i j sub
    for ((i = 1; i <= FPD; i++)); do
        : > "$dir/file_$i.dat"
    done
    if (( depth < DEPTH )); then
        for ((j = 1; j <= FANOUT; j++)); do
            sub="$dir/dir_$j"
            mkdir -p "$sub"
            gen "$sub" $((depth + 1))
        done
    fi
}

gen "$ROOT" 0
echo "tree: depth=$DEPTH fanout=$FANOUT filesPerDir=$FPD dirs=$(find "$ROOT" -type d | wc -l) files=$(find "$ROOT" -type f | wc -l)"
