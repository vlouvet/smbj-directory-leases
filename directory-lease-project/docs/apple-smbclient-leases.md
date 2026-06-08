# Apple SMBClient — Directory Lease / Lease Implementation (reference digest)

Source studied (READ ONLY): `/Users/v/code/smbj-dir-lease/reference/SMBClient`
(Apple's open-source kernel `smbfs` + `netsmb`). All references below are into that tree.

This is a digest of how Apple's SMB client implements SMB2/3 leasing, focused on
**directory leases** for caching directory enumerations, written as a porting reference for
a Java client (smbj).

---

## 0. High-level model

- Apple uses **LeaseV2** (`"RqLs"`, V2 layout) for directory leases. Dir leases are always V2.
- A **lease key** is per-node (per file/dir), 16 bytes, generated from a UUID, stored on the
  smbnode and reused for the lifetime of that node.
- A directory OPEN (the Create half of a `Create + QueryDirectory` compound) carries a LeaseV2
  create context requesting **HANDLE caching (+ READ)**. Granting the lease lets the client
  keep the directory handle open and trust its cached enumeration until the server breaks it.
- Leases are tracked in a **global hash table keyed by lease key** (`lease_key_hi ^ lease_key_low`),
  mapping lease key → vnode. This is how an async server lease-break is resolved back to a node.
- A **lease break** arrives as an unsolicited `SMB2 OPLOCK_BREAK` (0x12) message. For a dir lease,
  the client immediately invalidates the directory enumeration cache (`d_changecnt++` + name-cache
  purge), then closes the deferred dir handle (which is an *implicit* ack), else sends an explicit
  Lease Break Acknowledgement.
- **Epoch** (a uint16 in LeaseV2) orders lease-state changes so stale/reordered updates are ignored.

---

## 1. Lease key: generation, storage, uniqueness

Generated in `smb2_lease_init()` — `kernel/smbfs/smbfs_node.c:4750`:

```c
if (flags & SMB2_NEW_LEASE_KEY) {
    UInt8 uuid[16];
    uuid_generate(uuid);
    lease_keyp = (uint64_t *) &uuid[15];  leasep->lease_key_hi  = *lease_keyp;
    lease_keyp = (uint64_t *) &uuid[7];   leasep->lease_key_low = *lease_keyp;
}
```

- **Size:** 16 bytes. Held as two `uint64_t` halves: `lease_key_hi`, `lease_key_low`.
  (Note Apple's quirk: it reads two overlapping 8-byte windows out of a 16-byte UUID at
  offsets 15 and 7 — the exact byte derivation is not load-bearing for a port; just generate
  16 random bytes.)
- **Per-file/per-node**, NOT per-handle. The key lives on the smbnode and is reused:
  `struct smbnode { uint64_t n_lease_key_hi; n_lease_key_low; uint16_t n_epoch; struct smb2_lease n_lease; ... }`
  — `kernel/smbfs/smbfs_node.h:305-313`.
- A new key is only minted when `SMB2_NEW_LEASE_KEY` is passed (e.g. when first creating the
  node / dir-enum context). Otherwise `smb2_lease_init` copies the existing key from the node
  (`np->n_lease_key_hi/low`). Once granted, the node persists the key
  (`smbfs_smb_2.c:6498` etc.).

In-memory lease state struct — `struct smb2_lease`, `kernel/netsmb/smb_2.h:54-70`:

```c
struct smb2_lease {
    lck_mtx_t lock;
    uint64_t flags;             // internal _SMB_LEASE_FLAGS bits (see below)
    uint32_t req_lease_state;   // what we asked for
    uint32_t lease_state;       // what server granted / current
    uint64_t lease_key_hi, lease_key_low;
    uint64_t par_lease_key_hi, par_lease_key_low;   // parent dir's lease key
    uint16_t epoch;             // SMB 3.x LeaseV2
    int32_t  handle_reuse_cnt;
    time_t   def_close_timer;   // deferred-close timer
    uint32_t pending_break;
};
```

Internal flags — `enum _SMB_LEASE_FLAGS`, `kernel/smbfs/smbfs.h:213-223`:

```
SMB2_NEW_LEASE_KEY              = 0x0001   // request: mint a fresh key
SMB2_LEASE_PARENT_LEASE_KEY_SET = 0x0002
SMB2_LEASE_REQUESTED           = 0x0004
SMB2_LEASE_GRANTED             = 0x0008
SMB2_LEASE_V2                  = 0x0010
SMB2_LEASE_BROKEN              = 0x0020
SMB2_DEFERRED_CLOSE            = 0x0040
SMB2_LEASE_FAIL                = 0x0080
```

---

## 2. LeaseV2 create context on a directory OPEN + ParentLeaseKey threading

### Where the dir lease is requested
`smb2fs_smb_cmpd_query_dir()` — `kernel/smbfs/smbfs_smb_2.c:4342-4402`.
Conditions to request a dir lease:
- `SMBV_SMB3_OR_LATER(sessionp)` and
- session capability `SMB2_GLOBAL_CAP_DIRECTORY_LEASING` set, and
- mount not mounted with `SMBFS_MNT_DIR_LEASE_OFF`, and
- not a plain `readdir` (`f_is_readdir == 0`) — readdir doesn't cache.

When granted it sets `create_flags |= SMB2_CREATE_DIR_LEASE`, then:

```c
lease_flags = SMB2_LEASE_REQUESTED;
smb2_lease_init(ctx->f_share, NULL, ctx->f_dnp, lease_flags, &new_lease, 1);
new_lease.req_lease_state = SMB2_LEASE_HANDLE_CACHING | SMB2_FILE_READ_DATA;  // see §3
new_lease.epoch           = ctx->f_dnp->n_lease.epoch;
```

Important pattern: the lease is **added to the global lease table BEFORE the Create is sent**
(`smbfs_add_update_lease(..., SMBFS_LEASE_ADD, ...)`, `smbfs_smb_2.c:4376`) because a break can
arrive before the Create response. If the Create fails / no lease granted, it's removed
(`SMBFS_LEASE_REMOVE`). On success with `SMB2_LEASE_GRANTED`, the temp lease is folded into the
node lease via `SMBFS_LEASE_UPDATE` (`smbfs_smb_2.c:4519-4536`).

### Building the LeaseV2 create context (wire format)
`smb2_smb_add_create_contexts()` — `kernel/netsmb/smb_smb_2.c:655-704`. V2 chosen when dur-handle-V2
is supported OR `SMB2_CREATE_DIR_LEASE` is set (dir leases always V2):

```c
context_len += 80;
mb_reserve(next);                 // Next (chained context offset)
mb_put_uint16le(16);              // NameOffset
mb_put_uint16le(4);               // NameLength
mb_put_uint16le(0);               // Reserved
mb_put_uint16le(24);              // DataOffset
mb_put_uint32le(52);              // DataLength   <-- 52 == LeaseV2
mb_put_uint32be(SMB2_CREATE_REQUEST_LEASE_V2);  // "RqLs" name (0x52714c73), big-endian
mb_put_uint32le(0);               // pad to 8-byte boundary
mb_put_uint64le(lease_key_hi);    // LeaseKey (16 bytes)
mb_put_uint64le(lease_key_low);
mb_put_uint32le(lease_state);     // LeaseState (requested)
if (par_lease_key_hi && par_lease_key_low) {
    mb_put_uint32le(SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET);   // Flags = 0x00000004
    mb_put_uint64le(0);                                      // LeaseDuration (always 0)
    mb_put_uint64le(par_lease_key_hi);                       // ParentLeaseKey (16 bytes)
    mb_put_uint64le(par_lease_key_low);
} else {
    mb_put_uint32le(0);  mb_put_uint64le(0);                 // Flags=0, Duration=0
    mb_put_uint64le(0);  mb_put_uint64le(0);                 // ParentLeaseKey = 0
}
mb_put_uint16le(0);   // Epoch  ([MS-SMB2] 3.2.4.3.8: client sends 0 on the request)
mb_put_uint16le(0);   // Reserved
mb_put_uint32le(0);   // 4 bytes pad to 8-byte boundary
```

LeaseV1 (`smb_smb_2.c:705-727`) is the 32-byte data variant: LeaseKey(16) + LeaseState(4) +
LeaseFlags(4) + LeaseDuration(8). No ParentLeaseKey, no Epoch.

### How the ParentLeaseKey is found / threaded
`smb2_lease_init()` — `kernel/smbfs/smbfs_node.c:4808-4857`. Only filled when the session is
SMB2.1+ and has `SMB2_GLOBAL_CAP_LEASING`:

- If a parent dir node (`dnp`) is passed in → use `dnp->n_lease_key_hi/low` directly.
- Else (only `np` known) → walk to the parent via `smbfs_smb_get_parent(np, kShareLock)` and copy
  `VTOSMB(par_vp)->n_lease_key_hi/low`.
- Named-stream special case: parent is the *file* vnode; it walks file → parent-dir and uses the
  parent dir's key.
- If no parent can be found, ParentLeaseKey stays 0 → flag not set.

So the ParentLeaseKey is **the parent directory's own lease key**. This lets the server group a
child file's lease under the parent dir's lease so a child change can be signalled efficiently.
The `SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET` (0x4) flag is only set when ParentLeaseKey != 0.

---

## 3. Lease-state bits and what Apple requests for directories

State bits — `kernel/netsmb/smb_2.h:587-591`:

```
SMB2_LEASE_NONE           = 0x00
SMB2_LEASE_READ_CACHING   = 0x01   // R
SMB2_LEASE_HANDLE_CACHING = 0x02   // H  (lets client keep the handle open / defer close)
SMB2_LEASE_WRITE_CACHING  = 0x04   // W
```

`SMB2_OPLOCK_LEVEL_LEASE = 0xff` (`smb_2.h:582`) — the oplock-level value used in the Create
request to say "I'm using a lease, see the lease context".

**For directories Apple requests `SMB2_LEASE_HANDLE_CACHING | SMB2_FILE_READ_DATA`**
(`smbfs_smb_2.c:4394`). In practice the directory cares about the **H (handle)** bit: holding the
handle lease is what lets it keep the dir open across closes (deferred close) and trust the cached
enumeration. The `vnop_close` path keeps the dir open only while
`(n_lease.flags & SMB2_LEASE_GRANTED) && (n_lease.lease_state & SMB2_LEASE_HANDLE_CACHING)`
(`smbfs_vnops.c:1694-1703`).

For files (FYI), the requested level is computed in `smbfs_get_req_lease_state()`
(`smbfs_node.c:5378-5395`): always HANDLE, plus READ if `FILE_READ_DATA`, plus WRITE if
`FILE_WRITE_DATA`. A reconnect re-requests the *exact same* state already granted
(`smb_smb_2.c:633-636`).

---

## 4. Epoch handling (LeaseV2): upgrade/downgrade detection

- The node tracks `n_epoch`/`n_lease.epoch` (uint16). On a fresh request the client sends Epoch=0;
  the server returns its current epoch, which the client stores
  (`smb_smb_2.c:4585` parse, sets `leasep->epoch = server_epoch`).
- Server increments epoch by +1 on every state change ([MS-SMB2] 3.3.4.7).
- Delta computed by `smbfs_get_epoch_delta(server_epoch, file_epoch)` — `smbfs_node.c:5341`:
  - `==`  → 0 (no change; ignore).
  - server > file → `delta = server - file` (newer; apply).
  - file > server and `(file - server) > 32767` → wrap-around, server newer, apply delta.
  - file > server otherwise → `-1` (stale/reordered reply from server; **ignore**).
- **Upgrade vs downgrade detection** is in the `SMBFS_LEASE_UPDATE` path of
  `smbfs_add_update_lease()` — `smbfs_node.c:5062-5200+`. Only acts when `delta_epoch > 0`. It
  runs a state-transition matrix (old `lease_state` → new `in_leasep->lease_state`) deciding:
  - `upgrade = 1` (gained caching rights),
  - `purge_cache = 1` (lost read caching → must drop cached data),
  - `error` for impossible transitions (e.g. NONE→narrower).
  When there's no epoch (LeaseV1), it assumes `delta_epoch = 1` (always treat as valid/newer).
- In the break path (`smbfs_handle_lease_break`, `smbfs_node.c:5744-5794`): if `delta_epoch > 1`
  and the lease state didn't actually change, it flushes+purges UBC (it missed an intermediate
  state). If `delta_epoch <= 0` the break is effectively ignored.

---

## 5. Server-pushed lease break: receive → process → ack, and what's invalidated

### Receive / parse
An unsolicited `SMB2_OPLOCK_BREAK` is parsed by `smb2_smb_parse_lease_break()` —
`kernel/netsmb/smb_smb_2.c:6460`. **Lease Break Notification** body (struct size must be 44):

```
uint16 StructureSize = 44
uint16 NewEpoch
uint32 Flags                 // bit0 = SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED (0x01)
uint64 LeaseKeyHi
uint64 LeaseKeyLow
uint32 CurrentLeaseState
uint32 NewLeaseState
uint32 BreakReason           // ignored
uint32 AccessMaskHint        // ignored
uint32 ShareMaskHint         // ignored
```

It then calls `smb_iod_lease_enqueue(...)` (`smb_smb_2.c:6561`, impl `smb_iod.c:4118`), which:
1. **Immediately** (synchronously, no delay) calls `smbfs_handle_dir_lease_break(lease_rqp)` so the
   dir enum cache is invalidated right away.
2. Enqueues the request on `session_lease_list` and wakes the dedicated **lease thread** to do the
   slower work (close handle, send ack).

### Resolve lease key → node
`smbfs_lease_hash_get(lease_key_hi, lease_key_low)` (`smbfs_node.c:6149`) looks up the global hash
(`hashval = lease_key_hi ^ lease_key_low`, `SMBFS_LEASE_HASH`) to get the `smb_lease` entry, whose
`vnode`/`vid` give the node. Entries added/removed via `smbfs_lease_hash_add` (`smbfs_node.c:6108`)
and `smbfs_add_update_lease(... ADD/REMOVE/UPDATE ...)` (`smbfs_node.c:4916`).

### Dir-lease break handling (cache invalidation)
`smbfs_handle_dir_lease_break()` — `smbfs_node.c:5398`. After confirming the node is a VDIR and the
key matches `np->n_lease`:

```c
np->d_changecnt++;                       // *** invalidates the dir enumeration cache ***
np->n_lease.flags |= SMB2_LEASE_BROKEN;
np->n_lease.flags &= ~SMB2_LEASE_GRANTED;
np->n_lease.lease_state = new_lease_state;   // dir break ⇒ expected NONE
np->n_lease.epoch       = server_epoch;
cache_purge(vp);                         // purge VFS name cache for the dir
lease_rqp->need_close_dir = 1;           // tell lease thread to close the deferred dir handle
```

The directory enumeration caches live on the node:
`d_main_cache`, `d_overflow_cache`, `d_changecnt` (`smbfs_node.h:335-339`). Cache validity is keyed
off `d_changecnt`, so bumping it invalidates the cache without freeing it inline. Any local mutation
that should invalidate the cache also bumps `d_changecnt` (create/delete/rename in `smbfs_vnops.c`,
e.g. lines 2240, 7952, 9118).

### General break handling + ack
`smbfs_handle_lease_break()` (lease thread) — `smbfs_node.c:5570`. For files it maps lost bits to
cache actions: lost WRITE → flush UBC; lost READ → purge UBC; lost HANDLE with a deferred close →
close the fid. For dirs (`need_close_dir`), it removes the lease from the table, then
`smbfs_closedirlookup()` closes the directory handle.

**Acknowledgement:** A successful close is an *implicit* lease-break ack
([MS-SMB2] 3.2.5.19.2) → it sets `skip_lease_break = 1`. Otherwise, if
`flags & SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED`, it sends an explicit ack via
`smb2_smb_lease_break_ack_queue()` → `smb2_smb_lease_break_ack()` (`smb_smb_2.c:2999`):

**Lease Break Acknowledgement** request body (struct size 36):

```
uint16 StructureSize = 36
uint16 Reserved = 0
uint32 Flags = 0
uint64 LeaseKeyHi
uint64 LeaseKeyLow
uint32 LeaseState     // the new (reduced) lease state we are acknowledging
uint64 LeaseDuration = 0
```

Response is also struct size 36; client verifies the returned lease key matches.
The ack is sent on the same iod the break arrived on, and is signed if signing is in use.

---

## 6. Constants / struct-layout confirmations (wire format)

Create-context name (`kernel/netsmb/smb_2.h:690-691`):
```
SMB2_CREATE_REQUEST_LEASE     = 0x52714c73  // "RqLs"
SMB2_CREATE_REQUEST_LEASE_V2  = 0x52714c73  // "RqLs" (same name; V1 vs V2 distinguished by DataLength)
```
The 4-char name is written **big-endian** (`mb_put_uint32be`) so it appears as ASCII "RqLs" on the wire.

LeaseV2 create-context flag (`smb_2.h:704`):
```
SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET = 0x00000004
```

Lease-state bits (`smb_2.h:588-591`): NONE=0x00, READ=0x01, HANDLE=0x02, WRITE=0x04.
Oplock-level-lease sentinel (`smb_2.h:582`): `SMB2_OPLOCK_LEVEL_LEASE = 0xff`.
Break-notification ack-required flag (`smb_2.h:585`): `0x01`.

Lengths that distinguish V1 vs V2 in the create context **DataLength** field:
- **V1 lease context data = 32 bytes** (`smb_smb_2.c:718`): LeaseKey16 + State4 + Flags4 + Duration8.
- **V2 lease context data = 52 bytes** (`smb_smb_2.c:670`, parse check `:4544`):
  LeaseKey16 + State4 + Flags4 + Duration8 + ParentLeaseKey16 + Epoch2 + Reserved2.
  (Total V2 context incl. header/name/pad = 80 bytes.)

Message body struct sizes (used as validation):
- Lease Break **Notification** body = **44** (`smb_smb_2.c:6501`).
- Lease Break **Acknowledgement** request/response body = **36** (`smb_smb_2.c:3050`, `:3097`).

Session capability bits gating lease use:
- `SMB2_GLOBAL_CAP_LEASING` — required for file leasing / ParentLeaseKey threading.
- `SMB2_GLOBAL_CAP_DIRECTORY_LEASING` — required to request a directory lease
  (`smbfs_smb_2.c:4357`).

---

## 7. Porting checklist for smbj (the load-bearing essentials)

1. **Lease key:** generate 16 random bytes per directory node; store & reuse. Keep it stable for
   the node's lifetime. Maintain a `Map<leaseKey(16 bytes), DirNode>` so async breaks resolve.
2. **On dir OPEN** (the Create you already issue before Query Directory): if server negotiated
   `SMB2_GLOBAL_CAP_DIRECTORY_LEASING`, add a LeaseV2 ("RqLs", DataLength=52) create context with
   `RequestedOplockLevel = 0xff`, `LeaseState = HANDLE_CACHING (0x02)` (Apple OR's in READ_DATA but
   the operative cache bit is HANDLE), `ParentLeaseKey = parent dir's lease key` and
   `Flags = 0x04` when a parent lease key exists, `Epoch = 0`.
3. **Register the lease before sending** the Create (a break can race ahead of the response);
   unregister if not granted.
4. **On Create response:** parse the returned lease context; if granted with HANDLE caching, keep
   the directory handle open and treat your enumeration cache as authoritative. Store the returned
   epoch.
5. **On lease break (SMB2 OPLOCK_BREAK, body size 44):** match by lease key →
   - invalidate the directory enumeration cache (Apple's `d_changecnt++` equivalent: bump a
     generation counter / drop cache),
   - mark lease broken, update stored lease state + epoch (apply epoch-delta rule: ignore if
     `delta <= 0`),
   - close the deferred directory handle. **Closing the handle is an implicit ack.**
   - If you don't close, and `Flags & 0x01 (ACK_REQUIRED)`, send a Lease Break Acknowledgement
     (body size 36) with the lease key and the new (reduced) lease state.
6. **Epoch:** store server epoch; on any update/break only apply if `server_epoch > stored_epoch`
   (with wrap handling); ignore reordered/stale notifications.
7. **Capability gate:** only do any of this when the negotiate response advertised directory
   leasing; otherwise fall back to time-based cache expiry.
</content>
