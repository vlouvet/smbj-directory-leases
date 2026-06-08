#!/bin/bash
# Provision the SMB user (matching host uid/gid so bind-mounted files keep
# smbj ownership) and launch smbd in the foreground.
set -euo pipefail

SMB_USER="${SMB_USER:-smbj}"
SMB_PASSWORD="${SMB_PASSWORD:-changeit}"
SMB_UID="${SMB_UID:-1000}"
SMB_GID="${SMB_GID:-1000}"

# group/user matching the host owner of the bind mount
if ! getent group "$SMB_GID" >/dev/null 2>&1; then
    addgroup -g "$SMB_GID" "$SMB_USER"
fi
GRP_NAME="$(getent group "$SMB_GID" | cut -d: -f1)"
if ! id -u "$SMB_USER" >/dev/null 2>&1; then
    adduser -D -H -u "$SMB_UID" -G "$GRP_NAME" "$SMB_USER"
fi

# samba account
printf '%s\n%s\n' "$SMB_PASSWORD" "$SMB_PASSWORD" | smbpasswd -a -s "$SMB_USER"
smbpasswd -e "$SMB_USER" >/dev/null 2>&1 || true

mkdir -p /share /var/log/samba

echo "=== smbd version ==="
smbd --version
echo "=== effective directory-lease / protocol settings ==="
testparm -s 2>/dev/null | grep -iE "directory leases|min protocol|max protocol|oplocks" || true

exec smbd --foreground --no-process-group --debug-stdout
