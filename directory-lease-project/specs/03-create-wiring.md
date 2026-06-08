# 03 — Wiring Create-Contexts + Oplock/Lease Level into CREATE

> **IMPLEMENTED & VERIFIED LIVE (2026-06-07). Important correction below.**
> The request `writeTo` runs against a **`SigningBuffer`** (SMB3 signing wrapper) whose
> `wpos()` does NOT track the real write position. The `wpos()`-based offset/length backfill
> sketched here produced `CreateContextsLength = 0`, so Samba silently ignored the lease
> context and granted no lease (cost ~an hour to find — the unit tests passed because a plain
> `SMBBuffer`'s `wpos()` works). **Fix actually shipped:** compute the context block's
> header-relative offset from the constant name offset
> (`SMB2PacketHeader.STRUCTURE_SIZE + structureSize - 1`), serialize the contexts into a
> *standalone* `SMBBuffer`, and splice the bytes in with `putRawBytes` — **never call `wpos()`**
> in `writeTo` (mirrors how the existing `NameOffset` is computed). Byte-exact
> `SMB2CreateRequestSpec` still passes (identical on a plain buffer). Response parsing is
> unaffected (it reads a normal receive buffer via `getHeader().getHeaderStartPosition()`).

> Milestone 3 of `00-overview.md`. Depends on specs 01 (`SMB2CreateContext`
> read/write) and 02 (`SMB2OplockLevel`, lease primitives, `RqLs` V1/V2
> (de)serialize). TDD: write the failing specs in §6 first, implement to green,
> keep all 273 existing tests passing.

All paths below are relative to `smbj/` unless noted. Line anchors are from the
current checkout (read-only inspection performed; no source modified by this spec).

---

## 1. Purpose & scope

smbj currently never sends a create context and never reads one back:

- `messages/SMB2CreateRequest.java:65` hardcodes `RequestedOplockLevel = 0` (None).
- `messages/SMB2CreateRequest.java:93-94` hardcodes `CreateContextsOffset = 0` and
  `CreateContextsLength = 0`; the name is the last thing written (`:96`).
- `messages/SMB2CreateResponse.java:48` reads the `OplockLevel` byte and discards it.
- `messages/SMB2CreateResponse.java:49` reads `Flags` and discards it.
- `messages/SMB2CreateResponse.java:61-63` reads `CreateContextsOffset`/`Length`
  and explicitly ignores the contexts.

This spec wires the create-context machinery from spec 01 and the lease/oplock
types from spec 02 into the CREATE request/response:

- **Request:** accept an optional `List<SMB2CreateContext>` and a settable
  `SMB2OplockLevel`; serialize the contexts 8-byte aligned after the Name, using
  `SMB2CreateContext.writeAll`, and back-patch `CreateContextsOffset`/`Length`.
- **Response:** capture `OplockLevel` (as `SMB2OplockLevel`), capture `Flags`,
  parse the response context list via `SMB2CreateContext.readAll`, and expose a
  helper that extracts the lease (`RqLs`) response context.

**Backward compatibility is mandatory.** The existing public constructor
(`SMB2CreateRequest.java:44-59`) and the single call site
(`smbj/share/Share.java:154`) must keep compiling and behaving byte-for-byte
identically when no contexts and the default oplock level are used. A no-context
CREATE request must serialize to the *exact same bytes* it does today (regression
test in §6).

**Out of scope (later specs):** building the `RqLs` lease context payload (spec
02), `DiskShare.openDirectory` actually attaching a lease context and threading
ParentLeaseKey (spec 05), and break handling (spec 06).

---

## 2. Dependencies (specs 01, 02)

From `00-overview.md` "Naming & package conventions" — these are the canonical
APIs this spec consumes. They MUST exist (green) before implementing §4.

**Spec 01 — `com.hierynomus.mssmb2.messages.create.SMB2CreateContext`:**
- Value holder: `byte[] name` (4-char tag, e.g. `RqLs`), `byte[] data`.
- `static void writeAll(SMBBuffer buffer, List<SMB2CreateContext> contexts)` —
  writes each context with the 16-byte context header
  (`Next`, `NameOffset`, `NameLength`, `Reserved`, `DataOffset`, `DataLength`),
  then name, then data; handles 8-byte alignment *between* contexts and sets the
  `Next` chain (`Next = 0` on the last). Returns nothing; caller measures bytes
  written via buffer `wpos()` delta (see §5).
- `static List<SMB2CreateContext> readAll(SMBBuffer buffer, int offset, int length)`
  — repositions to `offset`, walks the `Next` chain for `length` bytes, returns
  the parsed contexts. (If spec 01 prefers a count-less `readAll(buffer, offset)`
  that loops until `Next == 0`, §4.2 adapts; assume the `(offset, length)` form.)
- `byte[] getName()` / `byte[] getData()`; a name-tag comparison helper
  (e.g. `hasName(byte[])` or `Arrays.equals(getName(), ...)`).

**Spec 02 — `com.hierynomus.mssmb2.SMB2OplockLevel`** (`EnumWithValue<SMB2OplockLevel>`):
- `NONE(0x00)`, `II(0x01)`, `EXCLUSIVE(0x08)`, `BATCH(0x09)`, `LEASE(0xFF)`.
- Used for both the request `RequestedOplockLevel` and the response `OplockLevel`.

**Spec 02 — `com.hierynomus.mssmb2.messages.create.SMB2LeaseResponseContext`:**
- Parses a `RqLs` response context's `data` (V1 32B / V2 52B, disambiguated by
  `DataLength`). The §4.2 helper builds one from the matching `SMB2CreateContext`.

The 4-char lease tag constant `"RqLs"` (ASCII `52 71 4C 73`) comes from spec 01/02
(e.g. `SMB2CreateContextType.RQLS` or a constant on `SMB2LeaseCreateContext`).

---

## 3. Wire layout — where contexts attach + the offset/length back-patch

### 3.1 CREATE Request ([MS-SMB2] 2.2.13)

The request buffer is built header-first: `SMB2Packet.write` calls
`header.writeTo(buffer)` (sets `headerStartPosition = buffer.wpos()`, which is `0`
for a fresh request buffer) then `writeTo(buffer)` (`SMB2Packet.java:72-73`). So in
a request, **absolute buffer position == offset-from-header-start**.

Fixed body is `structureSize = 57` (`SMB2CreateRequest.java:51`), but per [MS-SMB2]
the StructureSize includes 1 byte of the variable buffer, so the fixed portion is
56 bytes. The constant name offset is computed at `:74`:

```
offset = SMB2PacketHeader.STRUCTURE_SIZE + structureSize - 1
       = 64 + 57 - 1 = 120
```

i.e. the Name starts immediately after the 56-byte fixed body (`64 + 56`).

Layout (byte offsets relative to SMB2 header start):

```
  0..63    SMB2 header                                   (64 bytes)
 64..119   CREATE fixed body                             (56 bytes)
            ... StructureSize, SecurityFlags,
                RequestedOplockLevel  <-- §4.1 (a)         @ offset 66
                ImpersonationLevel, CreateFlags, Reserved,
                DesiredAccess, FileAttributes, ShareAccess,
                CreateDisposition, CreateOptions,
                NameOffset=120, NameLength,
                CreateContextsOffset  <-- back-patched     @ offset 108 (4 bytes)
                CreateContextsLength  <-- back-patched     @ offset 112 (4 bytes)
120..        Name (Unicode, NameLength bytes; 1 pad byte if root)
   [pad]     0..7 bytes so the first context is 8-byte aligned
 CC..        CreateContexts (chained, 8-byte aligned)     (CreateContextsLength)
```

`CreateContextsOffset`/`Length` are physically written at request offsets 108/112
(within the fixed body, at `SMB2CreateRequest.java:93-94`), but the actual context
*bytes* come after the variable-length Name. Therefore the values cannot be known
when the field is written — they must be **back-patched** after the Name + padding
+ contexts are emitted. (The write order today is: fixed body incl. the two zeroes
at `:93-94`, then `putRawBytes(nameBytes)` at `:96`. We append align+contexts after
`:96`, then patch the two fields.)

### 3.2 Byte math (back-patch)

Let `headerStart = header.getHeaderStartPosition()` (0 for a request).
Let `ccOffsetFieldPos` = the wpos captured *just before* `buffer.putUInt32(0)` at
`:93` (the position of the `CreateContextsOffset` field).

After writing the Name at `:96`:

1. `nameEnd = buffer.wpos()`.
2. `pad = (8 - ((nameEnd - headerStart) % 8)) % 8` → `putReserved(pad)` so the
   first context starts on an 8-byte boundary.
3. `ccStart = buffer.wpos()`. `createContextsOffset = ccStart - headerStart`.
4. `SMB2CreateContext.writeAll(buffer, contexts)`.
5. `ccEnd = buffer.wpos()`. `createContextsLength = ccEnd - ccStart`.
6. Back-patch: `buffer.putUInt32(ccOffsetFieldPos, createContextsOffset)` then
   `buffer.putUInt32(ccOffsetFieldPos + 4, createContextsLength)` (the positional
   `Buffer.putUInt32(int index, long)` overload writes without moving wpos).

**Empty / null context list:** skip steps 2-6 entirely; leave the two fields as the
`0` written at `:93-94`, and do NOT emit padding. This guarantees the no-context
request is byte-identical to today (the Name remains the last thing written).

### 3.3 CREATE Response ([MS-SMB2] 2.2.14)

The response is read via `SMB2Packet.read` → `readMessage(buffer)`
(`SMB2Packet.java:86-90`). The header was already parsed and `headerStartPosition`
set to the header's start rpos (`SMB2PacketHeader.java:176`). The response's
`CreateContextsOffset` is relative to the SMB2 header start, so:

```
absoluteContextPos = header.getHeaderStartPosition() + createContextsOffset
```

Response fixed body:

```
StructureSize(2) OplockLevel(1) Flags(1) CreateAction(4)
CreationTime(8) LastAccessTime(8) LastWriteTime(8) ChangeTime(8)
AllocationSize(8) EndOfFile(8) FileAttributes(4) Reserved2(4)
FileId(16) CreateContextsOffset(4) CreateContextsLength(4)
  [contexts at headerStart + CreateContextsOffset, CreateContextsLength bytes]
```

Parsing must, if `createContextsLength > 0`, call
`SMB2CreateContext.readAll(buffer, headerStart + createContextsOffset, createContextsLength)`.
`SMB2Packet.read` restores `buffer.rpos(messageEndPosition)` afterward
(`SMB2Packet.java:90`), so repositioning the read cursor inside `readMessage` is safe.

---

## 4. Files to change

### 4.1 `src/main/java/com/hierynomus/mssmb2/messages/SMB2CreateRequest.java`

**(a) New fields** (after `:41`, the `impersonationLevel` field):

```java
private final SMB2OplockLevel requestedOplockLevel;
private final List<SMB2CreateContext> createContexts;
```

(`SMB2OplockLevel` is in `com.hierynomus.mssmb2`, already imported via the
wildcard `import com.hierynomus.mssmb2.*;` at `:20`. Add
`import com.hierynomus.mssmb2.messages.create.SMB2CreateContext;`,
`import java.util.List;`, and `import java.util.Collections;`.)

**(b) Constructor overload (backward compat) — caller strategy:**

Keep the existing 10-arg constructor (`:44-59`) verbatim as a delegating overload
so `Share.java:154` and every other caller keep compiling unchanged. Add a new
12-arg constructor that takes the two new params; the old one forwards with
`SMB2OplockLevel.NONE` and `Collections.emptyList()`:

```java
// existing signature — now delegates (no caller change required)
public SMB2CreateRequest(SMB2Dialect smbDialect, long sessionId, long treeId,
        SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask,
        Set<FileAttributes> fileAttributes, Set<SMB2ShareAccess> shareAccess,
        SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions,
        SmbPath path) {
    this(smbDialect, sessionId, treeId, impersonationLevel, accessMask, fileAttributes,
         shareAccess, createDisposition, createOptions, path,
         SMB2OplockLevel.NONE, Collections.<SMB2CreateContext>emptyList());
}

// new signature — used by spec 05's lease open path
@SuppressWarnings("PMD.ExcessiveParameterList")
public SMB2CreateRequest(..., /* same 10 params */,
        SMB2OplockLevel requestedOplockLevel, List<SMB2CreateContext> createContexts) {
    super(57, smbDialect, SMB2MessageCommandCode.SMB2_CREATE, sessionId, treeId);
    ... // existing ensureNotNull assignments
    this.requestedOplockLevel = ensureNotNull(requestedOplockLevel, SMB2OplockLevel.NONE);
    this.createContexts = createContexts != null ? createContexts : Collections.<SMB2CreateContext>emptyList();
}
```

(If `SMB2OplockLevel` has no `EnumUtils.ensureNotNull` overload, default with a
plain ternary instead — confirm against spec 02's enum.)

**(c) `writeTo` — RequestedOplockLevel** at `:65`. Replace the hardcoded zero:

```java
buffer.putByte((byte) requestedOplockLevel.getValue()); // RequestedOpLockLevel (1 byte)
```

**(d) `writeTo` — capture the field position** at `:93`. Before writing the two
zeroes, capture `int ccFieldPos = buffer.wpos();` then keep the existing
`putUInt32(0)` / `putUInt32(0)` (they remain the default when no contexts).

**(e) `writeTo` — emit + back-patch** after the Name write at `:96`. Add (only when
`!createContexts.isEmpty()`) the align/write/back-patch from §3.2. Use
`buffer.putReserved(pad)` for alignment and the positional
`buffer.putUInt32(ccFieldPos, ccOffset)` / `buffer.putUInt32(ccFieldPos + 4, ccLength)`
overload to back-patch without disturbing `wpos`.

> Template precedent: `SMB2NegotiateRequest.writeTo` (`:77-91`) +
> `putNegotiateContextList` (`:101-111`) + the `negotiateContextOffset` math in
> `putNegotiateContextOrStartTime` (`:120-126`) implement the same
> offset/8-byte-align/`Next`-chained pattern. The difference here: negotiate writes
> the offset *before* knowing it via pre-computed alignment math; CREATE back-patches
> because the Name is variable-length and precedes the contexts.

### 4.2 `src/main/java/com/hierynomus/mssmb2/messages/SMB2CreateResponse.java`

**(a) New fields** (after `:43`, `fileId`):

```java
private SMB2OplockLevel oplockLevel;
private byte flags;
private List<SMB2CreateContext> createContexts = Collections.emptyList();
```

Add imports: `com.hierynomus.mssmb2.SMB2OplockLevel`,
`com.hierynomus.mssmb2.messages.create.SMB2CreateContext`,
`com.hierynomus.mssmb2.messages.create.SMB2LeaseResponseContext`,
`java.util.Collections`, `java.util.List`,
and `com.hierynomus.protocol.commons.EnumWithValue.EnumUtils`.

**(b) Capture OplockLevel** at `:48`. Replace `buffer.readByte();` with:

```java
oplockLevel = EnumUtils.valueOf(buffer.readByte() & 0xFF, SMB2OplockLevel.class, SMB2OplockLevel.NONE);
```

(mask `& 0xFF` because `0xFF` LEASE would otherwise sign-extend to `-1`.)

**(c) Capture Flags** at `:49`. Replace `buffer.readByte();` with
`flags = buffer.readByte();`.

**(d) Parse contexts** at `:61-63`. Replace the ignore block with:

```java
int createContextsOffset = (int) buffer.readUInt32(); // (4 bytes)
int createContextsLength = (int) buffer.readUInt32(); // (4 bytes)
if (createContextsLength > 0) {
    int abs = getHeader().getHeaderStartPosition() + createContextsOffset;
    createContexts = SMB2CreateContext.readAll(buffer, abs, createContextsLength);
}
```

`getHeader().getHeaderStartPosition()` exists (`SMB2PacketHeader.java:259`) and is
set during header parse (`:176`). `SMB2Packet.read` restores rpos afterward (`:90`).

**(e) Accessors + lease helper** (after `getFileId()` at `:90-92`):

```java
public SMB2OplockLevel getOplockLevel() { return oplockLevel; }
public byte getFlags() { return flags; }
public List<SMB2CreateContext> getCreateContexts() { return createContexts; }

/** @return the parsed RqLs lease response context, or null if none was granted. */
public SMB2LeaseResponseContext getLeaseResponseContext() {
    for (SMB2CreateContext ctx : createContexts) {
        if (Arrays.equals(ctx.getName(), SMB2LeaseCreateContext.NAME /* "RqLs" */)) {
            return SMB2LeaseResponseContext.read(ctx.getData()); // V1/V2 by DataLength
        }
    }
    return null;
}
```

(Exact `NAME`/`read` shapes come from spec 02; adapt the constant + parse entry
point to whatever spec 02 names them. Add `java.util.Arrays`.)

**Caller compatibility:** no response caller change is required — `createContexts`
defaults to an empty list, the new getters are purely additive, and existing
getters (`:66-92`) are untouched.

---

## 5. Method sketches (signatures + logic, not full impl)

`SMB2CreateRequest.writeTo(SMBBuffer)` — additions only:

```
... existing writes through CreateOptions ...
putByte(requestedOplockLevel.getValue())          // replaces the (byte)0 at :65
... NameOffset / NameLength ...
ccFieldPos = buffer.wpos()                          // :93 — remember field position
putUInt32(0); putUInt32(0)                          // keep defaults
putRawBytes(nameBytes)                              // :96
if (!createContexts.isEmpty()):
    headerStart = getHeader().getHeaderStartPosition()   // 0 for a request
    pad = (8 - ((buffer.wpos() - headerStart) % 8)) % 8
    putReserved(pad)
    ccStart = buffer.wpos()
    SMB2CreateContext.writeAll(buffer, createContexts)
    ccLen = buffer.wpos() - ccStart
    putUInt32(ccFieldPos,     ccStart - headerStart)     // back-patch Offset
    putUInt32(ccFieldPos + 4, ccLen)                     // back-patch Length
```

`SMB2CreateResponse.readMessage(SMBBuffer)` — additions only:

```
readUInt16()                                  // StructureSize
oplockLevel = EnumUtils.valueOf(readByte() & 0xFF, SMB2OplockLevel, NONE)  // :48
flags = readByte()                            // :49
... existing reads through FileId ...
ccOffset = (int) readUInt32(); ccLen = (int) readUInt32()    // :62-63
if ccLen > 0:
    createContexts = SMB2CreateContext.readAll(
        buffer, getHeader().getHeaderStartPosition() + ccOffset, ccLen)
```

`SMB2CreateResponse.getLeaseResponseContext()` → first `RqLs` ctx decoded via
`SMB2LeaseResponseContext`, else `null` (see §4.2(e)).

Confirm `SMBBuffer`/`Buffer` exposes the positional `putUInt32(int index, long value)`
overload (the Negotiate back-patch precedent implies a positional writer exists;
if it is named differently, e.g. a `putUInt32At`, adjust accordingly). If no
positional uint32 exists, fall back to: build the contexts in a temp `SMBBuffer`,
compute offset/length up front, write the real values at `:93-94`, then
`buffer.putBuffer(tempContexts)` after the Name + padding (`Buffer.putBuffer`
referenced in `docs/smbj-analysis.md` §1.1).

---

## 6. TDD tests (failing-first)

Extend the two Spock specs in `src/test/groovy/com/hierynomus/mssmb2/messages/`.
`SMB2CreateResponseSpec.groovy` exists (`AbstractPacketReadSpec`, `convert(bytes)`);
`SMB2CreateRequestSpec.groovy` does **not** exist yet — create it. Write all four
cases first and watch them fail, then implement §4 to green.

### 6.1 `SMB2CreateRequestSpec.groovy` (new file)

Request specs serialize and inspect bytes (there is no `convert` for outbound —
call `req.write(buffer)` on an `SMBBuffer` then read fields back / compare bytes).

**Test A — lease context emits correct offset/length/bytes + OplockLevel=0xFF.**

```
given:
  def leaseCtx = <build a RqLs SMB2CreateContext from spec 01/02 — e.g.
                  new SMB2LeaseCreateContext(leaseKey, RH_state, ...).asCreateContext()>
  def req = new SMB2CreateRequest(SMB2Dialect.SMB_3_1_1, 1L, 1L,
              SMB2ImpersonationLevel.Identification,
              EnumSet.of(AccessMask.GENERIC_READ),
              EnumSet.noneOf(FileAttributes), EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ),
              SMB2CreateDisposition.FILE_OPEN, EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE),
              new SmbPath("share", "dir"),
              SMB2OplockLevel.LEASE, [leaseCtx])
  def buf = new SMBBuffer()
when:
  req.write(buf)
  def bytes = buf.compactData ?? buf.getCompactData()      // raw wire bytes
then:
  bytes[66] == (byte) 0xFF                                  // RequestedOplockLevel @ header+66
  // read CreateContextsOffset @ header+108 (LE uint32) and Length @ header+112:
  def ccOff  = leUint32(bytes, 108)
  def ccLen  = leUint32(bytes, 112)
  ccOff % 8 == 0                                            // 8-byte aligned
  ccOff == nameEnd8Aligned                                  // == align8(120 + nameLen)
  ccLen == expectedContextLength                            // 16 hdr + 4 name + dataLen (+pad)
  // the RqLs tag appears at ccOff:
  new String(bytes, ccOff + 16, 4, "ASCII") == "RqLs"
```

(Helpers: a tiny `leUint32(byte[],int)` reads little-endian; `align8(x) = (x+7)&~7`.
For `SmbPath("share","dir")`, `nameLen = "dir".length()*2 = 6`, so first context
offset `= align8(120 + 6) = align8(126) = 128`.)

**Test B — no-context CREATE is byte-identical to today (regression).**

Build *two* requests with identical args via the **old 10-arg constructor** and the
new one with `SMB2OplockLevel.NONE, []`; assert both produce identical bytes, and
critically that those bytes match a captured golden of the pre-change output:

```
expect:
  Arrays.equals(oldCtorBytes, newCtorBytes)
  bytes[66] == (byte) 0x00                       // RequestedOplockLevel still None
  leUint32(bytes, 108) == 0                       // CreateContextsOffset still 0
  leUint32(bytes, 112) == 0                       // CreateContextsLength still 0
  bytes.length == fixedBody(120) + nameLen        // no trailing padding/contexts
```

### 6.2 `SMB2CreateResponseSpec.groovy` (extend)

Reuse the existing `convert(bytes)` harness (`AbstractPacketReadSpec`).

**Test C — granted-lease response parses OplockLevel=LEASE + yields lease ctx.**

Hand-craft a CREATE response hex with `OplockLevel = 0xFF`, a non-zero
`CreateContextsOffset`/`Length`, and one `RqLs` V2 (DataLength=52) response context
encoding e.g. `LeaseState = READ|HANDLE`:

```
when:  def resp = convert(bytes) as SMB2CreateResponse
then:
  resp.oplockLevel == SMB2OplockLevel.LEASE
  resp.leaseResponseContext != null
  resp.leaseResponseContext.leaseState == EnumSet.of(READ_CACHING, HANDLE_CACHING)
  resp.leaseResponseContext.leaseKey == <expected LeaseKey>
```

Derive the hex from `docs/ms-smb2-lease-spec.md`'s `RqLs` V2 byte layout (spec 02
already has byte-exact vectors — reuse the same lease-key/state bytes so the
fixtures line up).

**Test D — existing no-context responses still parse (regression).**

The two existing cases (`SMB2CreateResponseSpec.groovy:27,43`) must stay green
unchanged. Add an explicit assertion to the first that
`resp.getCreateContexts().isEmpty()` and `resp.getLeaseResponseContext() == null`
and `resp.getOplockLevel() == SMB2OplockLevel.NONE` (that fixture has
`OplockLevel = 0x00` and `CreateContextsLength = 0`).

---

## 7. Acceptance criteria

1. `SMB2CreateRequest` has a new 12-arg constructor taking `SMB2OplockLevel` +
   `List<SMB2CreateContext>`; the original 10-arg constructor still exists and
   delegates with `NONE` + empty list. No existing caller (incl.
   `smbj/share/Share.java:154`) needs edits.
2. With a non-empty context list, the request serializes the contexts 8-byte
   aligned after the Name via `SMB2CreateContext.writeAll`, and back-patches
   `CreateContextsOffset` (= aligned position from header start) and
   `CreateContextsLength` (= bytes written). `RequestedOplockLevel` reflects the
   passed level (`0xFF` for `LEASE`).
3. With an empty/null context list and `SMB2OplockLevel.NONE`, the request is
   **byte-identical** to the current output (Test B), including `RequestedOplockLevel
   = 0x00`, both context fields `= 0`, and no trailing padding.
4. `SMB2CreateResponse` exposes `getOplockLevel()` (`SMB2OplockLevel`), `getFlags()`,
   `getCreateContexts()`, and `getLeaseResponseContext()` (the decoded `RqLs`
   response context, or `null`). Context parsing uses
   `header.getHeaderStartPosition() + createContextsOffset` and
   `SMB2CreateContext.readAll`.
5. Tests A-D pass (written failing-first). The existing
   `SMB2CreateResponseSpec.groovy` cases remain green unmodified (beyond the added
   assertions in Test D).
6. **All 273 existing tests still green** (`./gradlew clean build`), and the change
   compiles to Java 8 (`build.gradle options.release = 8`).
