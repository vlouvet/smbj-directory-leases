#!/bin/bash
# Deploy the lease-UNAWARE Samba (old-server arm) on .12:1446, same testshare bind mount.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=smbj-dirlease-old:4.20
NAME=smbj-dirlease-old
SHARE_HOST=/home/smbj/smbj-dirlease/testshare

# reuse the new server's entrypoint
cp ../entrypoint.sh ./entrypoint.sh

docker rm -f "$NAME" 2>/dev/null || true
docker build -t "$IMAGE" .

docker run -d --name "$NAME" \
  -p 1446:445 \
  -v "$SHARE_HOST":/share \
  -e SMB_USER=smbj -e SMB_PASSWORD=changeit -e SMB_UID=1000 -e SMB_GID=1000 \
  --restart unless-stopped \
  "$IMAGE"

sleep 3
docker ps --filter "name=$NAME" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
docker logs "$NAME" 2>&1 | grep -iE "Version |directory leases|protocol" | head
