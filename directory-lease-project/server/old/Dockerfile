# Lease-UNAWARE Samba (Alpine 3.21 => Samba 4.20.x, < 4.22) for the benchmark's
# "old server" arm. Same share/creds as the new server; runs on .12:1446.
# Alpine 3.21 is a stable release so base musl matches its samba package (no apk upgrade needed).
FROM alpine:3.21

RUN apk add --no-cache samba samba-common-tools bash \
 && rm -rf /var/cache/apk/*

COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 445
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
