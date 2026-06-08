#!/bin/bash
# Deploy the isolated Samba dir-lease test server on .12.
# Idempotent: rebuilds the image and recreates the container.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=smbj-dirlease:4.23
NAME=smbj-dirlease
SHARE_HOST=/home/smbj/smbj-dirlease/testshare

docker rm -f "$NAME" 2>/dev/null || true
# --pull: refresh alpine:edge so base musl matches the edge samba package
docker build --pull -t "$IMAGE" .

docker run -d --name "$NAME" \
  -p 1445:445 \
  -v "$SHARE_HOST":/share \
  -e SMB_USER=smbj -e SMB_PASSWORD=changeit -e SMB_UID=1000 -e SMB_GID=1000 \
  --restart unless-stopped \
  "$IMAGE"

sleep 3
echo "=== container status ==="
docker ps --filter "name=$NAME" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
echo "=== version / settings ==="
docker logs "$NAME" 2>&1 | grep -iE "Version |directory leases|protocol|oplocks" | head
