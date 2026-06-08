# 02 — Lease Data Model + `RqLs` Lease Create-Context Payloads

> Milestone 2 of `00-overview.md`. Builds on milestone 1 (`01-create-contexts.md`,
> the generic `SMB2CreateContext` TLV read/write). Deliverable: `LeaseKey`,
> `SMB2LeaseState`, `SMB2LeaseFlags`, `SMB2OplockLevel`, and the `RqLs` V1/V2
> request + response payloads, all proven with **byte-exact** offline unit tests.

---

## 1. Purpose & scope

Add the lease **data model** and the **`RqLs` create-context payloads** so that an
SMB2 CREATE can request a lease (V1 for SMB 2.1 file leases, V2 for SMB 3.x file /
**directory** leases) and the matching CREATE response lease context can be parsed.

In scope:

- `LeaseKey` — 16-byte value object (UUID-derived), `equals`/`hashCode`, so it can key
  a `Map<LeaseKey, …>` lease table (milestone 5).
- `SMB2LeaseState` — `EnumWithValue` bitmask (`NONE`/R/H/W) + set-membership helpers
  (`isReadHandle`, etc.).
- `SMB2LeaseFlags` — `EnumWithValue` (request `PARENT_LEASE_KEY_SET`; response also
  surfaces `BREAK_IN_PROGRESS`).
- `SMB2OplockLevel` — `EnumWithValue` (`NONE`/`II`/`EXCLUSIVE`/`BATCH`/`LEASE`),
  replacing the hardcoded `0` at `SMB2CreateRequest.java:65`.
- `SMB2LeaseCreateContext` — **request** payload writer: emits the V1 (32B) or
  V2 (52B) `RqLs` data blob and wraps it in an `SMB2CreateContext` (name `"RqLs"`).
- `SMB2LeaseResponseContext` — **response** payload parser: reads the V1/V2 data blob,
  **disambiguated by `DataLength` (32 vs 52)**, exposing granted state + keys + epoch.

Out of scope (later milestones): wiring contexts into `SMB2CreateRequest`/`Response`
(03), negotiate capability gating (04), open-with-lease + `LeaseManager` (05), break
handling (06). This milestone produces only the model + (de)serializers and their
unit tests; nothing is sent over the wire yet.

---

## 2. Dependencies (spec 01)

This milestone consumes the generic create-context TLV from milestone 1:

```
com.hierynomus.mssmb2.messages.create.SMB2CreateContext     // value holder (name 4CC, data byte[])
  static void writeAll(SMBBuffer, List<SMB2CreateContext>)  // 8-byte align + Next chaining
  static List<SMB2CreateContext> readAll(SMBBuffer, int offset, int length)
  byte[] getName()                                          // 4-byte 4CC, network order
  byte[] getData()                                          // payload blob
```

- `SMB2LeaseCreateContext` **produces** an `SMB2CreateContext` (`name = "RqLs"`,
  `data = <32|52-byte blob>`); spec-01's `writeAll` handles the surrounding TLV header,
  name, 8-byte alignment of name+data, and `Next` chaining. This spec is responsible
  **only** for the bytes *inside* `data`.
- `SMB2LeaseResponseContext` is **fed** an `SMB2CreateContext` already located+sliced by
  spec-01's `readAll` (matched on the `"RqLs"` 4CC); this spec parses `getData()`.
- This decoupling is why the V1-vs-V2 rule lives here on `DataLength` = `data.length`
  (32 vs 52) — spec 01 never needs to understand lease semantics.

If milestone 1 is not yet merged, the test harness may stub `SMB2CreateContext` as a
trivial `{byte[] name; byte[] data}` holder; the byte vectors in §6 stay valid because
they assert the inner blob and the fully-wrapped context independently.

---

## 3. Wire format

All integers **little-endian** except the create-context **name 4CC**, which is the four
ASCII bytes `R q L s` in **network (big-endian) order** = `0x52 0x71 0x4C 0x73`
(`0x52714C73`). Confirmed by Apple `mb_put_uint32be(SMB2_CREATE_REQUEST_LEASE_V2)`.

### 3.1 `RqLs` create-context name

| Const | Value | On-wire bytes (offset of name within the wrapped TLV) |
|-------|-------|--------------------------------------------------------|
| `SMB2_CREATE_REQUEST_LEASE` / `…_V2` | `0x52714C73` | `52 71 4C 73` ("RqLs") |

V1 and V2 share the **identical** 4CC. The only on-wire discriminator is `DataLength`.

### 3.2 V1 request data — `SMB2_CREATE_REQUEST_LEASE` (32 bytes, 0x20)

| Field         | Offset | Size | Value on request |
|---------------|--------|------|------------------|
| `LeaseKey`    | 0      | 16   | client lease key |
| `LeaseState`  | 16     | 4    | requested state bitmask (§3.6) |
| `LeaseFlags`  | 20     | 4    | reserved on request — MUST be 0 |
| `LeaseDuration` | 24   | 8    | reserved — MUST be 0 |

### 3.3 V2 request data — `SMB2_CREATE_REQUEST_LEASE_V2` (52 bytes, 0x34)

| Field            | Offset | Size | Value on request |
|------------------|--------|------|------------------|
| `LeaseKey`       | 0      | 16   | client lease key |
| `LeaseState`     | 16     | 4    | requested state (dirs: R or RH) |
| `Flags`          | 20     | 4    | `PARENT_LEASE_KEY_SET (0x04)` iff a parent key is set, else 0 |
| `LeaseDuration`  | 24     | 8    | reserved — MUST be 0 |
| `ParentLeaseKey` | 32     | 16   | parent dir's lease key (all-zero when flag clear) |
| `Epoch`          | 48     | 2    | client **MUST set 0** on initial request |
| `Reserved`       | 50     | 2    | MUST be 0 |

### 3.4 V1 response data — `SMB2_CREATE_RESPONSE_LEASE` (32 bytes)

Same layout as 3.2. `LeaseKey` echoed; `LeaseState` = **granted** state; `LeaseFlags`
may carry `BREAK_IN_PROGRESS (0x02)`; `LeaseDuration` = 0.

### 3.5 V2 response data — `SMB2_CREATE_RESPONSE_LEASE_V2` (52 bytes)

Same layout as 3.3. `LeaseState` = **granted** state (dirs: R or RH, never W);
`Flags` may carry `BREAK_IN_PROGRESS (0x02)` and/or `PARENT_LEASE_KEY_SET (0x04)`;
`ParentLeaseKey` echoed when flag set; `Epoch` = server's `Lease.Epoch`.

### 3.6 `LeaseState` bitmask

| Name | Value |
|------|-------|
| `SMB2_LEASE_NONE`           | `0x00` |
| `SMB2_LEASE_READ_CACHING`   | `0x01` (R) |
| `SMB2_LEASE_HANDLE_CACHING` | `0x02` (H) |
| `SMB2_LEASE_WRITE_CACHING`  | `0x04` (W) |

Useful granted combos: `NONE(0)`, `R(0x1)`, `RH(0x3)`, `RW(0x5)`, `RWH(0x7)`.
On the wire `LeaseState` is a 4-byte field; only the low byte is ever non-zero here.

### 3.7 V1-vs-V2 by `DataLength` (the load-bearing rule)

- **Request:** the *caller* chooses V1 or V2 by dialect (2.1 → V1 file only; 3.x → V2).
  This spec exposes both; the dialect decision is milestone 03/05. V2 emits `DataLength=52`,
  V1 emits `DataLength=32`.
- **Response parse:** branch **purely** on `data.length` (== the context's `DataLength`):
  - `32` → parse V1 (no `ParentLeaseKey`/`Epoch`; those read as absent/0).
  - `52` → parse V2.
  - anything else → throw (malformed `RqLs` payload).
  Never key off the 4CC — V1 and V2 share it.

### 3.8 Directory rule (informational; enforced server-side, asserted in IT later)

A directory open requests **R** or **RH** only. The **server strips
`WRITE_CACHING`** during oplock acquisition when the open is a directory
(`FILE_ATTRIBUTE_DIRECTORY`), so a directory is granted at most **RH**. The client may
still *send* whatever state it likes; this model does not pre-strip W (Apple requests
`HANDLE|READ_DATA` and lets the server decide). The useful directory lease is **RH**.

### 3.9 Worked V2 request layout (used by the §6 byte vector)

`LeaseKey = 000102…0F`, `LeaseState = RH (0x03)`, `Flags = PARENT_LEASE_KEY_SET (0x04)`,
`ParentLeaseKey = 101112…1F`, `Epoch = 0`. Inner 52-byte `data`:

```
off 0x00  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   LeaseKey
off 0x10  03 00 00 00                                       LeaseState = RH
off 0x14  04 00 00 00                                       Flags = PARENT_LEASE_KEY_SET
off 0x18  00 00 00 00 00 00 00 00                           LeaseDuration = 0
off 0x20  10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F   ParentLeaseKey
off 0x30  00 00                                             Epoch = 0
off 0x32  00 00                                             Reserved = 0
```

Wrapped as a single, last (`Next=0`) create context (header 16 + name "RqLs" 4 + pad 4 →
data at offset 24), the full context bytes are:

```
00 00 00 00   Next = 0 (last)
10 00         NameOffset = 16
04 00         NameLength = 4
00 00         Reserved = 0
18 00         DataOffset = 24
34 00 00 00   DataLength = 52
52 71 4C 73   "RqLs"
00 00 00 00   pad to 8-byte align before data
<the 52 data bytes above>
```

Total wrapped length = 24 + 52 = **76 bytes** (no trailing pad on the last context).

---

## 4. Files to add

Lease primitives — package `com.hierynomus.mssmb2`:

```
smbj/src/main/java/com/hierynomus/mssmb2/LeaseKey.java
smbj/src/main/java/com/hierynomus/mssmb2/SMB2LeaseState.java
smbj/src/main/java/com/hierynomus/mssmb2/SMB2LeaseFlags.java
smbj/src/main/java/com/hierynomus/mssmb2/SMB2OplockLevel.java
```

Lease create-context payloads — package `com.hierynomus.mssmb2.messages.create`:

```
smbj/src/main/java/com/hierynomus/mssmb2/messages/create/SMB2LeaseCreateContext.java
smbj/src/main/java/com/hierynomus/mssmb2/messages/create/SMB2LeaseResponseContext.java
```

Tests — `smbj/src/test/groovy/com/hierynomus/mssmb2/...`:

```
smbj/src/test/groovy/com/hierynomus/mssmb2/LeaseKeySpec.groovy
smbj/src/test/groovy/com/hierynomus/mssmb2/SMB2LeaseStateSpec.groovy
smbj/src/test/groovy/com/hierynomus/mssmb2/messages/create/SMB2LeaseCreateContextSpec.groovy
smbj/src/test/groovy/com/hierynomus/mssmb2/messages/create/SMB2LeaseResponseContextSpec.groovy
```

---

## 5. Class / method sketches

> Signatures + key logic only; not full implementations. Use `EnumWithValue` exactly as
> `SMB2GlobalCapability`/`SMB2CreateOptions` do, and the `SMBBuffer` put/read style of
> `SMB2NegotiateContext`. `SMBBuffer` provides `putRawBytes`/`readRawBytes(16)`,
> `putUInt16`/`readUInt16`, `putUInt32`/`readUInt32`, `putUInt64`/`putReserved(n)`.

### 5.1 `LeaseKey`

```java
public final class LeaseKey {
    public static final int SIZE = 16;
    private final byte[] key; // exactly 16 bytes (defensive copy in/out)

    public LeaseKey(byte[] key);                 // require key.length == 16, else IAE
    public static LeaseKey random();             // UUID.randomUUID() -> 16 bytes (per-node key)
    public static LeaseKey fromUuid(UUID uuid);  // 8 MSB + 8 LSB, big-endian, 16 bytes
    public byte[] getBytes();                    // defensive copy

    @Override public boolean equals(Object o);   // Arrays.equals on the 16 bytes
    @Override public int hashCode();             // Arrays.hashCode(key)
    @Override public String toString();          // hex
}
```

- Value object so it can key `Map<LeaseKey, LeasedDirectory>` (milestone 5) and match an
  inbound break's `LeaseKey` (milestone 6). `equals`/`hashCode` are the load-bearing part.
- `random()` mirrors Apple's per-node 16-byte UUID-derived key (exact byte derivation is
  not load-bearing; 16 random bytes suffice).
- A canonical **all-zero** key (`new LeaseKey(new byte[16])`) represents "no parent key".

### 5.2 `SMB2LeaseState`

```java
public enum SMB2LeaseState implements EnumWithValue<SMB2LeaseState> {
    SMB2_LEASE_NONE(0x00L),
    SMB2_LEASE_READ_CACHING(0x01L),
    SMB2_LEASE_HANDLE_CACHING(0x02L),
    SMB2_LEASE_WRITE_CACHING(0x04L);
    SMB2LeaseState(long v); public long getValue();

    // set helpers operating on the raw 4-byte bitmask (long):
    public static boolean isRead(long s);        // (s & 0x1) != 0
    public static boolean isHandle(long s);      // (s & 0x2) != 0
    public static boolean isWrite(long s);       // (s & 0x4) != 0
    public static boolean isReadHandle(long s);  // (s & 0x3) == 0x3   (RH)
    public static long readHandle();             // 0x3
}
```

- Reuse `EnumWithValue.EnumUtils.toLong(set)` / `toEnumSet(long, SMB2LeaseState.class)` for
  set <-> long conversion at the boundary; the `isXxx` helpers above are thin wrappers so
  callers (cache, break handler) read clearly. Implement them via `EnumUtils.isSet`.

### 5.3 `SMB2LeaseFlags`

```java
public enum SMB2LeaseFlags implements EnumWithValue<SMB2LeaseFlags> {
    SMB2_LEASE_FLAG_NONE(0x00L),
    SMB2_LEASE_FLAG_BREAK_IN_PROGRESS(0x02L),       // response-only
    SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET(0x04L);    // V2 request + response
    SMB2LeaseFlags(long v); public long getValue();
}
```

### 5.4 `SMB2OplockLevel`

```java
public enum SMB2OplockLevel implements EnumWithValue<SMB2OplockLevel> {
    SMB2_OPLOCK_LEVEL_NONE(0x00L),
    SMB2_OPLOCK_LEVEL_II(0x01L),
    SMB2_OPLOCK_LEVEL_EXCLUSIVE(0x08L),
    SMB2_OPLOCK_LEVEL_BATCH(0x09L),
    SMB2_OPLOCK_LEVEL_LEASE(0xFFL);
    SMB2OplockLevel(long v); public long getValue();
}
```

- This is a single-byte field in CREATE req/resp. `LEASE = 0xFF` means "see the `RqLs`
  context". Wiring it into `SMB2CreateRequest`/`Response` is milestone 03; defining the
  enum here lets that milestone drop the magic `0`.

### 5.5 `SMB2LeaseCreateContext` (request payload writer)

```java
public class SMB2LeaseCreateContext {
    public static final byte[] NAME = {0x52, 0x71, 0x4C, 0x73}; // "RqLs", network order
    public enum Version { V1, V2 }

    private final Version version;
    private final LeaseKey leaseKey;
    private final long leaseState;         // bitmask (use SMB2LeaseState helpers)
    private final LeaseKey parentLeaseKey; // V2 only; null/zero => flag clear
    private final long flags;              // derived: PARENT_LEASE_KEY_SET iff parent set

    // factories
    public static SMB2LeaseCreateContext v1(LeaseKey key, long leaseState);
    public static SMB2LeaseCreateContext v2(LeaseKey key, long leaseState,
                                            LeaseKey parentLeaseKey); // null => no parent

    /** Serialize just the inner data blob (32 or 52 bytes). */
    public byte[] toBytes();

    /** Wrap into the generic create-context (name "RqLs", data = toBytes()). */
    public SMB2CreateContext toCreateContext();
}
```

Key logic — `toBytes()`:

```
SMBBuffer b = new SMBBuffer();
b.putRawBytes(leaseKey.getBytes());     // 16
b.putUInt32(leaseState);                // 4   (low byte carries R/H/W)
b.putUInt32(flags);                     // 4   V1: always 0; V2: 0x04 iff parent set
b.putReserved(8);                       // LeaseDuration = 0
if (version == V2) {
    byte[] pk = (parentLeaseKey != null) ? parentLeaseKey.getBytes() : new byte[16];
    b.putRawBytes(pk);                  // 16  ParentLeaseKey (zero when no parent)
    b.putUInt16(0);                     // 2   Epoch — ALWAYS 0 on request (MS-SMB2 3.2.4.x)
    b.putReserved2();                   // 2   Reserved
}
return b.getCompactData();              // 32 (V1) or 52 (V2)
```

- **Flags derivation:** in `v2(...)`, set `flags |= PARENT_LEASE_KEY_SET (0x04)` iff
  `parentLeaseKey != null` and it is not the all-zero key; otherwise `flags = 0` and the
  `ParentLeaseKey` field is written as 16 zero bytes. `v1(...)` always writes `flags = 0`.
- **Epoch defaults to 0 on request** — hardcoded in the V2 branch; the client never sends a
  non-zero epoch on an initial lease request.
- `toCreateContext()` returns `new SMB2CreateContext(NAME, toBytes())`; spec-01's `writeAll`
  supplies the TLV header, name placement, 8-byte alignment, and `Next` chaining.

### 5.6 `SMB2LeaseResponseContext` (response payload parser)

```java
public class SMB2LeaseResponseContext {
    private final boolean v2;
    private final LeaseKey leaseKey;
    private final long leaseState;          // GRANTED state
    private final long flags;               // BREAK_IN_PROGRESS / PARENT_LEASE_KEY_SET
    private final LeaseKey parentLeaseKey;  // V2 only, else null
    private final int epoch;                // V2 only, else 0

    /** Parse the inner data blob; V1/V2 chosen by data.length (32 vs 52). */
    public static SMB2LeaseResponseContext read(byte[] data) throws Buffer.BufferException;

    /** Convenience over an already-located "RqLs" context (spec 01 readAll). */
    public static SMB2LeaseResponseContext from(SMB2CreateContext ctx);

    public LeaseKey getLeaseKey();
    public long getLeaseState();
    public boolean isReadHandleGranted();   // SMB2LeaseState.isReadHandle(leaseState)
    public LeaseKey getParentLeaseKey();    // null on V1
    public int getEpoch();                  // 0 on V1
    public boolean isV2();
}
```

Key logic — `read(byte[] data)`:

```
boolean v2;
switch (data.length) {
    case 32: v2 = false; break;
    case 52: v2 = true;  break;
    default: throw new SMBRuntimeException("Bad RqLs response DataLength: " + data.length);
}
SMBBuffer b = new SMBBuffer(data);
LeaseKey key = new LeaseKey(b.readRawBytes(16));
long state   = b.readUInt32();
long flags   = b.readUInt32();
b.skip(8);                                  // LeaseDuration
if (v2) {
    LeaseKey parent = new LeaseKey(b.readRawBytes(16));
    int epoch = b.readUInt16();
    b.skip(2);                              // Reserved
    return new SMB2LeaseResponseContext(true, key, state, flags, parent, epoch);
}
return new SMB2LeaseResponseContext(false, key, state, flags, null, 0);
```

- `from(ctx)` asserts `Arrays.equals(ctx.getName(), SMB2LeaseCreateContext.NAME)` then
  delegates to `read(ctx.getData())`.
- V1 path leaves `parentLeaseKey = null`, `epoch = 0` (callers must check `isV2()` before
  trusting epoch). This is the **only** place the V1/V2 fork is decided — strictly by length.

---

## 6. TDD tests (failing-first)

Spock specs under `src/test/groovy/...`. Write them **before** the impl; each must fail to
compile/red first, then go green. Use `ByteArrayUtils.parseHex` for vectors (as in
`SMB2CreateResponseSpec`). Helper constants:

```
LeaseKey       = 000102030405060708090A0B0C0D0E0F
ParentLeaseKey = 101112131415161718191A1B1C1D1E1F
```

### 6.1 `LeaseKeySpec`

- `new LeaseKey(byte[15])` throws `IllegalArgumentException`.
- Two `LeaseKey`s built from the same 16 bytes are `equals` and share `hashCode`; a
  differing byte makes them unequal. Confirms usability as a `Map` key.
- `getBytes()` returns a copy (mutating the result does not change the key).
- `random()` yields 16 bytes and two calls differ.

### 6.2 `SMB2LeaseStateSpec`

- `isRead/isHandle/isWrite/isReadHandle` truth table: `0x0→none`, `0x1→R`, `0x3→RH`,
  `0x5→RW`, `0x7→RWH`. Assert `isReadHandle(0x3)==true`, `isReadHandle(0x1)==false`,
  `isReadHandle(0x2)==false`, `readHandle()==0x3`.
- Round-trip `EnumUtils.toLong(EnumSet.of(READ_CACHING,HANDLE_CACHING)) == 0x3` and
  `toEnumSet(0x3,…)` contains exactly R+H.

### 6.3 `SMB2LeaseCreateContextSpec` — **byte-exact build**

**Case A — V2 RH request with parent + flag (the directory case).** Build
`v2(LeaseKey, RH=0x3, ParentLeaseKey)`:

- Assert `toBytes()` equals exactly the **52** bytes:

```
000102030405060708090A0B0C0D0E0F  03000000  04000000  0000000000000000
101112131415161718191A1B1C1D1E1F  0000      0000
```
  hex: `000102030405060708090a0b0c0d0e0f0300000004000000000000000000000010111213141516171819
1a1b1c1d1e1f00000000`

- Assert the **wrapped** create-context bytes (single, last context) equal exactly **76**
  bytes:

```
00000000 1000 0400 0000 1800 34000000 52714c73 00000000
000102030405060708090a0b0c0d0e0f 03000000 04000000 0000000000000000
101112131415161718191a1b1c1d1e1f 0000 0000
```
  (Produced by feeding `toCreateContext()` to spec-01 `SMB2CreateContext.writeAll(buf, [ctx])`.)

**Case B — V2 RH request, no parent.** `v2(LeaseKey, 0x3, null)`: bytes at offset 0x14
(`Flags`) are `00 00 00 00`, and `ParentLeaseKey` (offset 0x20) is 16 zero bytes; total
still 52. Confirms flag is **only** set when a parent key is present.

**Case C — V1 request.** `v1(LeaseKey, R=0x1)`: `toBytes()` is exactly **32** bytes:

```
000102030405060708090a0b0c0d0e0f 01000000 00000000 0000000000000000
```
  No `ParentLeaseKey`/`Epoch`. Confirms `DataLength=32`.

**Case D — Epoch is always 0 on request.** Even when constructed via the V2 factory, bytes
at offset 0x30..0x31 (`Epoch`) are `00 00`. (No setter exposes a request epoch.)

### 6.4 `SMB2LeaseResponseContextSpec` — **parse + disambiguation**

**Case A — parse V2 response granting RH.** Feed the 52-byte blob:

```
000102030405060708090a0b0c0d0e0f 03000000 04000000 0000000000000000
101112131415161718191a1b1c1d1e1f 0500 0000
```
  (granted `RH`, `PARENT_LEASE_KEY_SET`, `Epoch=5`). Assert: `isV2()==true`,
  `getLeaseKey()==LeaseKey(0001..0F)`, `getLeaseState()==0x3`, `isReadHandleGranted()==true`,
  `getParentLeaseKey()==LeaseKey(1011..1F)`, `getEpoch()==5`.

**Case B — parse V1 response.** Feed the 32-byte blob:

```
000102030405060708090a0b0c0d0e0f 01000000 00000000 0000000000000000
```
  Assert: `isV2()==false`, `getLeaseState()==0x1`, `isReadHandleGranted()==false`,
  `getParentLeaseKey()==null`, `getEpoch()==0`.

**Case C — DataLength disambiguation.** A `byte[40]` (neither 32 nor 52) makes `read(...)`
throw. A 32-byte input is parsed as V1 (never reading a `ParentLeaseKey`); a 52-byte input
as V2. Parameterize over `[32→V1, 52→V2]` asserting `isV2()` matches and that V1 leaves
`epoch==0`/`parent==null`.

**Case D — round-trip.** `read(SMB2LeaseCreateContext.v2(key, 0x3, parent).toBytes())`
yields back `leaseKey==key`, `leaseState==0x3`, `parentLeaseKey==parent`, `epoch==0`
(request epoch). Proves writer/parser symmetry on the V2 blob.

> All four specs must be **red before** any `main/` class exists, then green after.

---

## 7. Acceptance criteria

1. New files exist exactly at the §4 paths and packages; enums implement
   `EnumWithValue<…>` with the §3.6/§5 values; no magic numbers leak.
2. `SMB2LeaseCreateContext.toBytes()` is **byte-exact**: V2 = 52 bytes, V1 = 32 bytes,
   matching the §6.3 vectors; `Epoch` is always `00 00` on request; `Flags` carries
   `PARENT_LEASE_KEY_SET (0x04)` **iff** a non-zero parent key is supplied.
3. `toCreateContext()` + spec-01 `writeAll` produces the exact 76-byte wrapped context in
   §3.9 / §6.3 Case A (name "RqLs" `52 71 4C 73`, `NameOffset=16`, `DataOffset=24`,
   `DataLength=52`, `Next=0`).
4. `SMB2LeaseResponseContext.read(...)` disambiguates **solely** by `data.length`
   (32→V1, 52→V2, else throw) and exposes granted `LeaseState`, `LeaseKey`, and (V2)
   `ParentLeaseKey` + `Epoch` + `Flags`; V1 yields `parentLeaseKey==null`, `epoch==0`.
5. `LeaseKey` `equals`/`hashCode` make it a valid `Map` key; constructor rejects non-16-byte
   input; `getBytes()` returns a defensive copy.
6. `SMB2LeaseState.isReadHandle` and friends return the §6.2 truth table.
7. All four Spock specs pass; the existing `build` test suite stays green (no changes to
   `SMB2CreateRequest`/`Response` yet — that is milestone 03).
8. Nothing in this milestone sends bytes on the wire or touches negotiate/create wiring;
   it is pure model + (de)serialization with offline byte-vector proof.
