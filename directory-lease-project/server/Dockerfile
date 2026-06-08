# Samba 4.23.x (Alpine edge) with SMB3 directory leases enabled.
# Built/run on .12; exposes container :445 -> host :1445.
FROM alpine:edge

# apk upgrade first: the samba package on edge is built against a newer musl
# than the (possibly cached) base layer, otherwise smbd fails to relocate
# `renameat2` (musl symbol mismatch -> exit 127 crash loop).
RUN apk --no-cache upgrade \
 && apk add --no-cache samba samba-common-tools bash \
 && rm -rf /var/cache/apk/*

COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 445
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
