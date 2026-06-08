# MS-SMB2 Lease Wire-Protocol Spec Digest (Directory-Lease Focused)

Implementer-oriented digest of SMB2/3 leasing, focused on **directory leases**. Field
tables give names, byte sizes, offsets, and concrete values so serializers/parsers can be
built directly. All multi-byte integers are **little-endian** unless a value is noted as
"network byte order" (the create-context name 4CC). Sources are cited inline.

Primary spec: **[MS-SMB2]** on Microsoft Learn. Samba behavior from the Samba 4.22 release
notes and wiki.

---

## 0. Quick directory-lease cheat sheet

- A directory lease is just a normal SMB2 lease taken on an open whose
  `FileAttributes`/create options mark it a directory (`FILE_DIRECTORY_FILE`).
- It requires the **V2** lease create context (`SMB2_CREATE_REQUEST_LEASE_V2`), which only
  exists in the **SMB 3.x** dialect family. SMB 2.1 (V1) leases are **files only** — a 2.1
  lease request with `FILE_DIRECTORY_FILE` MUST be failed `STATUS_NOT_SUPPORTED`.
- Directories may request **R** and **H** only ("RH"). **Write caching (W) is always
  stripped** by the server for directories — see §3.3.5.9.11 rule below.
- Server must advertise `SMB2_GLOBAL_CAP_DIRECTORY_LEASING (0x20)` in NEGOTIATE; client
  must select an SMB 3.x dialect and use `RequestedOplockLevel = SMB2_OPLOCK_LEVEL_LEASE
  (0xFF)`.
- The V2 context carries a `ParentLeaseKey` + `SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET
  (0x04)` linking a child open to its enclosing directory's lease — this is what lets the
  server break the parent directory lease when a child is created/renamed/deleted.

---

## 1. Create-context mechanism: `SMB2_CREATE_CONTEXT`

Source: [MS-SMB2] 2.2.13.2 SMB2_CREATE_CONTEXT Request Values
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/75364667-3a93-4e2c-b771-592d8d5e876d>

A create context is a self-describing TLV. Both requests and responses use the same outer
structure; contexts are chained via `Next`.

| Field        | Offset | Size | Notes |
|--------------|--------|------|-------|
| `Next`       | 0      | 4    | Offset (bytes) from start of *this* context to the next 8-byte-aligned context. **0 = last context.** |
| `NameOffset` | 4      | 2    | Offset from start of this structure to the 8-byte-aligned name. |
| `NameLength` | 6      | 2    | Length in bytes of the context name (4 for the lease 4CC). |
| `Reserved`   | 8      | 2    | MUST be 0 on send; ignored on receipt. |
| `DataOffset` | 10     | 2    | Offset from start of this structure to the 8-byte-aligned data payload. If `DataLength`==0, SHOULD be 0 and server ignores. |
| `DataLength` | 12     | 4    | Length in bytes of the data payload. Type of payload is inferred from the name. |
| `Buffer`     | 16     | var  | Holds the name then the data, positioned per the offsets above. |

Fixed header is **16 bytes**, then a variable `Buffer`.

**Alignment / chaining rules (load-bearing):**
- Each context's name and data MUST be **8-byte aligned** (relative to start of the SMB2
  header, which is itself 8-byte aligned in the response/request).
- Successive contexts MUST begin at the first 8-byte-aligned offset after the previous one;
  `Next` encodes that distance. Last context has `Next = 0`.
- There is **no required ordering** of multiple contexts; a server MUST accept any order.
- Typical lease layout: header(16) + name "RqLs"(4) + 4 bytes pad → data at offset 24,
  then the lease data blob. `NameOffset=16, NameLength=4, DataOffset=24`.

**Create-context name 4CCs** (in *network byte order*; the listed hex is the 4 ASCII bytes):

| Name | 4CC hex | ASCII |
|------|---------|-------|
| `SMB2_CREATE_REQUEST_LEASE`     | `0x52714C73` | **"RqLs"** |
| `SMB2_CREATE_REQUEST_LEASE_V2`  | `0x52714C73` | **"RqLs"** (same 4CC!) |
| `SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2` | `0x44483251` | "DH2Q" |
| `SMB2_CREATE_QUERY_ON_DISK_ID`  | `0x51466964` | "QFid" |

**Critical:** V1 and V2 lease contexts share the identical name **"RqLs"**. The server/client
disambiguates **purely by `DataLength`**: V1 = 32 bytes, V2 = 52 bytes
(<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/75364667-3a93-4e2c-b771-592d8d5e876d>).

---

## 2. `SMB2_CREATE_REQUEST_LEASE` (V1)

Source: [MS-SMB2] 2.2.13.2.8
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/250a5100-f8b0-4b32-a202-f592ce4c05e7>

This is the **data payload** of the "RqLs" create context for SMB **2.1**. Not valid for
2.0.2. Files only.

| Field           | Offset | Size | Notes |
|-----------------|--------|------|-------|
| `LeaseKey`      | 0      | 16   | Client-generated key identifying the lease owner. |
| `LeaseState`    | 16     | 4    | Requested lease state (see §4). |
| `LeaseFlags`    | 20     | 4    | Reserved in request; client MUST set 0, server ignores. |
| `LeaseDuration` | 24     | 8    | Reserved; MUST be 0. |

**Total payload size = 32 bytes (0x20).**

---

## 3. `SMB2_CREATE_REQUEST_LEASE_V2`

Source: [MS-SMB2] 2.2.13.2.10
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/32c16a84-123f-40a9-99a8-00d34964308f>

Data payload of "RqLs" for **SMB 3.x** only. **This is the structure directory leases use.**

| Field            | Offset | Size | Notes |
|------------------|--------|------|-------|
| `LeaseKey`       | 0      | 16   | Client-generated lease owner key. |
| `LeaseState`     | 16     | 4    | Requested lease state (see §4). Directories: R / RH only. |
| `Flags`          | 20     | 4    | Combination of lease flags; here `SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET (0x04)` (see §5). |
| `LeaseDuration`  | 24     | 8    | Reserved; MUST be 0. |
| `ParentLeaseKey` | 32     | 16   | Lease key of the **parent directory**'s lease (valid only when the flag bit is set). |
| `Epoch`          | 48     | 2    | uint16 lease-state-change counter. Client SHOULD set 0 on initial request. |
| `Reserved`       | 50     | 2    | MUST be 0. |

**Total payload size = 52 bytes (0x34).**

**V1 vs V2 selection (client rule, 3.2.4.x "Requesting a Lease on a File or a Directory"):**
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/50855e7c-0d71-41b7-a005-cc08f728c03a>
- `Connection.Dialect == "2.0.2"` → fail `STATUS_NOT_SUPPORTED` (no leasing).
- `Connection.Dialect == "2.1"` → attach **V1** context. If create options include
  `FILE_DIRECTORY_FILE` → fail `STATUS_NOT_SUPPORTED` (no dir leases on 2.1).
- `Connection.Dialect` in **SMB 3.x family** → attach **V2** context.

---

## 4. Lease state flags (`LeaseState`, 4 bytes, bitmask)

Source: 2.2.13.2.10 / 2.2.13.2.11
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1bccd8d3-a13e-4288-9c7b-26e498052a25>

| Name | Value | Meaning |
|------|-------|---------|
| `SMB2_LEASE_NONE`          | `0x00000000` | No lease. |
| `SMB2_LEASE_READ_CACHING`  | `0x00000001` | Read caching ("R"). |
| `SMB2_LEASE_HANDLE_CACHING`| `0x00000002` | Handle caching ("H"). |
| `SMB2_LEASE_WRITE_CACHING` | `0x00000004` | Write caching ("W"). |

**Valid combinations** (Windows-granted set; conventional shorthand): `NONE`, `R` (0x1),
`RH` (0x3), `RW` (0x5), `RWH` (0x7). Handle caching without read (`H` alone, `WH`) and
write without read (`W` alone) are not meaningful granted states; `W` implies `R`.

**Directory leases:** request and are granted **R** or **RH** only. The server **MUST clear
`SMB2_LEASE_WRITE_CACHING`** during Oplock Acquisition when
`FileAttributes` includes `FILE_ATTRIBUTE_DIRECTORY`
(<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fc4f8879-f295-4995-b71e-21f309d8d7c8>).
So directories cannot get write caching regardless of what the client asks for. The useful
directory lease is **RH** (cache the directory listing + keep the handle to avoid re-open
churn).

Server also strips `W` if `TreeConnect.Share.ForceLevel2Oplock` is TRUE, and for
`STYPE_CLUSTER_SOFS` shares collapses `LeaseState` to at most `R` (else `NONE`).

---

## 5. Lease flags (`Flags`, 4 bytes) and the parent-lease-key linkage

In the **V2 request** `Flags` field:

| Name | Value | Meaning |
|------|-------|---------|
| `SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET` | `0x00000004` | `ParentLeaseKey` field is populated. |

In **responses** (V1 `LeaseFlags` / V2 `Flags`) the server may additionally set:

| Name | Value | Meaning |
|------|-------|---------|
| `SMB2_LEASE_FLAG_BREAK_IN_PROGRESS`     | `0x00000002` | A break for this lease key is in progress. |
| `SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET`  | `0x00000004` | (V2 response) `ParentLeaseKey` echoed. |

**Parent-lease-key role for directory leases** (client rule, 3.2.4.x):
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/50855e7c-0d71-41b7-a005-cc08f728c03a>
- When opening any file/dir, the client searches `GlobalFileTable` for the **parent
  directory** (path with the last component removed).
- If an entry exists, the client copies that entry's `File.LeaseKey` into the new request's
  `ParentLeaseKey` and sets `SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET (0x04)`.
- Server stores it as `Lease.ParentLeaseKey`
  (<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fc4f8879-f295-4995-b71e-21f309d8d7c8>).
- This linkage is what allows the object store to **break the parent directory's lease**
  when a child entry changes (create/rename/delete/attribute change inside the directory),
  invalidating the cached listing.
- For a named stream (`name:stream`), the client SHOULD clear `SMB2_LEASE_HANDLE_CACHING`.

---

## 6. Responses

### 6a. `SMB2_CREATE_RESPONSE_LEASE` (V1)
Source: 2.2.14.2.10
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a60d6c95-15ca-4c69-816e-c145506108a3>

| Field           | Offset | Size | Notes |
|-----------------|--------|------|-------|
| `LeaseKey`      | 0      | 16   | Echoed lease key. |
| `LeaseState`    | 16     | 4    | **Granted** lease state. |
| `LeaseFlags`    | 20     | 4    | May contain `SMB2_LEASE_FLAG_BREAK_IN_PROGRESS (0x02)`. |
| `LeaseDuration` | 24     | 8    | Reserved, 0. |

**Total = 32 bytes.**

### 6b. `SMB2_CREATE_RESPONSE_LEASE_V2`
Source: 2.2.14.2.11
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1bccd8d3-a13e-4288-9c7b-26e498052a25>

| Field            | Offset | Size | Notes |
|------------------|--------|------|-------|
| `LeaseKey`       | 0      | 16   | Echoed. |
| `LeaseState`     | 16     | 4    | **Granted** state (directories: R or RH; never W). |
| `Flags`          | 20     | 4    | `SMB2_LEASE_FLAG_BREAK_IN_PROGRESS (0x02)` and/or `SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET (0x04)`. |
| `LeaseDuration`  | 24     | 8    | Reserved, 0. |
| `ParentLeaseKey` | 32     | 16   | Echoed if `Lease.ParentLeaseKey` non-empty (and flag set). |
| `Epoch`          | 48     | 2    | `Lease.Epoch` (incremented on each state change). |
| `Reserved`       | 50     | 2    | 0. |

**Total = 52 bytes.** Server increments `Lease.Epoch` by 1 whenever it promotes the lease
state.

### 6c. Surrounding SMB2 CREATE Response fields
Source: 2.2.14
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d166aa9e-0b53-410e-b35e-3933d8131927>

- `StructureSize` (2) = 89.
- `OplockLevel` (1 byte, offset 2): for a lease this is **`SMB2_OPLOCK_LEVEL_LEASE = 0xFF`**.
  When 0xFF, the response MUST carry an `SMB2_CREATE_RESPONSE_LEASE`/`_V2` context.
  Other values: `NONE 0x00`, `II 0x01`, `EXCLUSIVE 0x08`, `BATCH 0x09`.
- `Flags` (1 byte, offset 3): SMB 3.x only; `SMB2_CREATE_FLAG_REPARSEPOINT = 0x01`.
- `CreateContextsOffset` (4) / `CreateContextsLength` (4): locate the response create
  contexts (the lease context lives here).

---

## 7. Negotiate capabilities

Source: 2.2.4 SMB2 NEGOTIATE Response, `Capabilities` field (4 bytes)
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5>

| Name | Value | Notes |
|------|-------|-------|
| `SMB2_GLOBAL_CAP_DFS`                | `0x00000001` | |
| `SMB2_GLOBAL_CAP_LEASING`           | `0x00000002` | File leasing. Not valid for 2.0.2. |
| `SMB2_GLOBAL_CAP_LARGE_MTU`         | `0x00000004` | |
| `SMB2_GLOBAL_CAP_MULTI_CHANNEL`     | `0x00000008` | |
| `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES`| `0x00000010` | |
| `SMB2_GLOBAL_CAP_DIRECTORY_LEASING` | `0x00000020` | **Directory leasing.** SMB 3.0+ only (invalid for 2.0.2 / 2.1). |
| `SMB2_GLOBAL_CAP_ENCRYPTION`        | `0x00000040` | 3.0 / 3.0.2. |

Dialect revisions: `2.0.2=0x0202`, `2.1=0x0210`, `3.0=0x0300`, `3.0.2=0x0302`,
`3.1.1=0x0311`.

**Client requirements for directory leasing:**
- Negotiate an **SMB 3.x** dialect (3.0, 3.0.2, or 3.1.1).
- Set `SMB2_GLOBAL_CAP_LEASING` (and `SMB2_GLOBAL_CAP_DIRECTORY_LEASING`) in its own
  NEGOTIATE request capabilities; server confirms support via its NEGOTIATE response
  capabilities. (`Connection.SupportsFileLeasing` / directory-leasing state is derived from
  the server's response —
  <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b29f3af-86f9-4962-8cf3-43471cb59363>.)
- Send CREATE with `RequestedOplockLevel = SMB2_OPLOCK_LEVEL_LEASE (0xFF)` + V2 "RqLs"
  context. If the server lacks `SMB2_GLOBAL_CAP_DIRECTORY_LEASING`, it ignores the V2
  context for a directory open and grants no lease.

---

## 8. Lease break flow

Command for all break messages: **SMB2 OPLOCK_BREAK = `0x0012`** (the same command carries
oplock breaks and lease breaks; lease form is distinguished by `StructureSize` 44).

### 8a. Lease Break **Notification** (server → client, async)
Source: 2.2.23.2
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9abe6f73-f32f-4a23-998d-ee9da2b90e2e>

Header: `Command = 0x0012`, `MessageId = 0xFFFFFFFFFFFFFFFF`, `SessionId = 0`, `TreeId = 0`,
SHOULD NOT be signed.

| Field              | Offset | Size | Notes |
|--------------------|--------|------|-------|
| `StructureSize`    | 0      | 2    | MUST be **44**. |
| `NewEpoch`         | 2      | 2    | uint16. SMB 3.x + `Lease.Version==2`: `Lease.Epoch+1`. Else 0 (e.g. SMB 2.1). |
| `Flags`            | 4      | 4    | `SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED = 0x01` when an ack is required. |
| `LeaseKey`         | 8      | 16   | `Lease.LeaseKey`. |
| `CurrentLeaseState`| 24     | 4    | State before break. |
| `NewLeaseState`    | 28     | 4    | Target state (one of NONE, R, RW, RH per object store). |
| `BreakReason`      | 32     | 4    | Reserved, 0. |
| `AccessMaskHint`   | 36     | 4    | Reserved, 0. |
| `ShareMaskHint`    | 40     | 4    | Reserved, 0. |

**Total = 44 bytes** (excl. header).

### 8b. Lease Break **Acknowledgment** (client → server request)
Source: 2.2.24.2
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/048aae06-3421-418b-85b3-0f7605749596>

Sent only when the notification had the ACK_REQUIRED flag. Command `0x0012`.

| Field           | Offset | Size | Notes |
|-----------------|--------|------|-------|
| `StructureSize` | 0      | 2    | MUST be **36**. |
| `Reserved`      | 2      | 2    | 0. |
| `Flags`         | 4      | 4    | Reserved, 0. |
| `LeaseKey`      | 8      | 16   | Same lease key. |
| `LeaseState`    | 24     | 4    | Accepted state; MUST be a **subset** of the granted state in the notification. |
| `LeaseDuration` | 28     | 8    | Reserved, 0. |

**Total = 36 bytes.**

### 8c. Lease Break **Response** (server → client)
Source: 2.2.25.2
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9c814bbb-43a2-46fe-94d8-d713a58cd702>

Same 36-byte layout as the ack: `StructureSize=36`, `Reserved(2)=0`, `Flags(4)=0`,
`LeaseKey(16)`, `LeaseState(4)` = final granted state, `LeaseDuration(8)=0`.

### 8d. Break semantics — when is an ack required?
Source: "Object Store Indicates a Lease Break" 3.3.4.7
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c367fad4-c00f-4778-913d-c0560ead1360>

- If `Lease.LeaseState == SMB2_LEASE_READ_CACHING` (i.e. current state is just **R**), the
  server sets **`Flags = 0` (no ack required)**, drops opens to OplockState "None",
  `Lease.Breaking = FALSE`. So a pure read-caching break is a **one-way** notification.
- **Otherwise** (state includes H and/or W, e.g. **RH** directory lease), the server sets
  **`Flags = SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED (0x01)`**, marks opens "Breaking",
  sets `Lease.Breaking = TRUE`, starts the lease-break-ack timer, and waits for the client
  ack. The client must then send a Lease Break Acknowledgment whose `LeaseState` is a
  subset of `NewLeaseState`.

**Directory-lease specifics:**
- A directory lease is at most **RH**. When the directory's content changes (a child entry
  is created/renamed/deleted, or its attributes change — surfaced via the
  `ParentLeaseKey` linkage), the object store indicates a break, typically **RH → R** (keep
  reading cached but invalidate handle/listing caching) or down to **NONE**.
- Because the current state contains **H** (not pure R), the break to RH-minus-H (or below)
  **requires an ack** (`ACK_REQUIRED` set). The client must flush its cached directory
  listing and ack with the reduced state.
- A break that leaves the lease at pure **R** and is then *further* broken would, at that
  point, be ack-less per the rule above (current state == R → no ack).
- If `NewLeaseState` drops `SMB2_LEASE_HANDLE_CACHING` and the open is durable, or the open
  is non-durable/non-resilient/non-persistent with no available connection, the server
  closes the opens instead of notifying.
- `NewEpoch = Lease.Epoch + 1` for V2 leases lets the client detect races/stale breaks.

---

## 9. Samba specifics (4.22+)

Sources:
- Samba 4.22.0 release notes: <https://www.samba.org/samba/history/samba-4.22.0.html>
- Samba 4.22 Features added/changed (wiki): <https://wiki.samba.org/index.php/Samba_4.22_Features_added/changed>
- smb.conf(5): <https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html>

- **New smb.conf option:** `smb3 directory leases` (global). Controls whether the server
  advertises/grants SMB3 directory leases. Introduced in **Samba 4.22**.
- **Default = `Auto`.** Auto resolves to **enabled on non-clustered** Samba and **disabled
  on clustered** Samba, keyed off the `clustering` option. (Clustered/CTDB deployments
  disable it because the cross-node lease/break coordination needed for directory leases is
  not provided there.)
- **What it does:** lets SMB3 clients cache directory listings / child-object metadata,
  cutting repeated `QUERY_DIRECTORY`/metadata round-trips. Server tracks child changes and
  breaks the parent directory lease (RH → R / NONE) when contents change.
- **Requires** an SMB 3.x dialect connection; the server advertises
  `SMB2_GLOBAL_CAP_DIRECTORY_LEASING (0x20)` only when this option is effectively enabled.
- **Known issues / interop quirks to watch for in testing:**
  - 4.22.2 (BUG 15861): roaming/profile **sync failures attributed to directory leases** —
    a regression where directory-lease caching interfered with profile directory updates.
    Relevant if testing roaming-profile or rapidly-mutating directories.
  - 4.22.6 (BUG 15933): *"Only increment lease epoch if a lease was granted"* — earlier
    builds could bump `Lease.Epoch` even when no lease was granted, producing inconsistent
    `Epoch` values across CREATE responses / break notifications. Interop clients that
    validate epoch monotonicity should test against ≥ 4.22.6 or tolerate the quirk.
  - General interop note: because V1 and V2 share the "RqLs" 4CC and differ only by
    `DataLength`, a parser that keys off the name alone will misinterpret directory (V2)
    leases — always branch on the 52-byte vs 32-byte payload length.

---

## Appendix: constant summary

```
Create-context name "RqLs"                         = 0x52714C73 (network order ASCII)
SMB2_OPLOCK_LEVEL_LEASE                             = 0xFF
SMB2_LEASE_NONE                                     = 0x00000000
SMB2_LEASE_READ_CACHING   (R)                       = 0x00000001
SMB2_LEASE_HANDLE_CACHING (H)                       = 0x00000002
SMB2_LEASE_WRITE_CACHING  (W)                       = 0x00000004
SMB2_LEASE_FLAG_BREAK_IN_PROGRESS                   = 0x00000002
SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET                = 0x00000004
SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED           = 0x00000001
SMB2_GLOBAL_CAP_LEASING                             = 0x00000002
SMB2_GLOBAL_CAP_DIRECTORY_LEASING                   = 0x00000020
SMB2 OPLOCK_BREAK command                           = 0x0012
SMB2_CREATE_FLAG_REPARSEPOINT                       = 0x01

Structure sizes (data payload / StructureSize):
  SMB2_CREATE_CONTEXT fixed header                  = 16 bytes
  SMB2_CREATE_REQUEST_LEASE  (V1) data              = 32 bytes (0x20)
  SMB2_CREATE_REQUEST_LEASE_V2    data              = 52 bytes (0x34)
  SMB2_CREATE_RESPONSE_LEASE (V1) data              = 32 bytes
  SMB2_CREATE_RESPONSE_LEASE_V2   data              = 52 bytes
  Lease Break Notification  StructureSize           = 44
  Lease Break Acknowledgment StructureSize          = 36
  Lease Break Response       StructureSize          = 36
  CREATE Response            StructureSize           = 89
  NEGOTIATE Response         StructureSize           = 65
```
