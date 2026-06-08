# Spec 01 — Generic SMB2 CREATE-Context (de)serialization

## 1. Purpose & scope

Add a general, **lease-agnostic** SMB2 CREATE-context (de)serialization layer to smbj:
a value holder plus the wire codec for the `SMB2_CREATE_CONTEXT` TLV container
([MS-SMB2] 2.2.13.2). This is the connective tissue every create context (lease,
durable handle, query-on-disk-id, …) rides on.

In scope:
- New class `com.hierynomus.mssmb2.messages.create.SMB2CreateContext` — a `{name, data}`
  byte-array holder.
- Static `SMB2CreateContext.writeAll(SMBBuffer, List<SMB2CreateContext>)` — serializes a
  chained list: 16-byte header per context, name then data, 8-byte alignment of name/data
  and of each successive context, `Next`-offset backfill (0 on the last).
- Static `SMB2CreateContext.readAll(SMBBuffer, int offset, int length)` — parses a chained
  list back into `List<SMB2CreateContext>` by following `Next` until 0 (or `length`
  exhausted), positioning by the per-context `NameOffset` / `DataOffset`.
- A failing-first Spock spec exercising the codec byte-for-byte.

Explicitly **out of scope** (later specs):
- Any knowledge of the `"RqLs"` 4CC, lease V1/V2 payloads, or `DataLength`-based
  disambiguation → **spec 02** (`02-lease-model.md`). This layer treats `name` and `data`
  as opaque `byte[]`.
- Wiring the codec into `SMB2CreateRequest.writeTo` / `SMB2CreateResponse.readMessage`
  (offset/length backfill, oplock level) → **spec 03** (`03-create-wiring.md`). This spec
  only notes the backfill points (see §4).

## 2. Dependencies

- **None** on other specs. This is milestone 1 and must land green first.
- Depends only on existing smbj infrastructure: `com.hierynomus.smb.SMBBuffer` and its
  `com.hierynomus.protocol.commons.buffer.Buffer` base (`wpos()/wpos(int)`, `rpos()/rpos(int)`,
  `putUInt16/putUInt32`, `readUInt16/readUInt32`, `putRawBytes/readRawBytes`, `putReserved`,
  `skip`, `available`).
- Templates to mirror (study, do not modify): `messages/negotiate/SMB2NegotiateContext.java`
  (header write/read + per-context 8-byte alignment), `SMB2NegotiateRequest.putNegotiateContextList`
  (inter-context padding loop), `SMB2NegotiateResponse.readNegotiateContextList` (rpos-seek +
  loop). Downstream consumers are **spec 02** (lease payloads in `data`) and **spec 03**
  (request/response wiring).

## 3. Wire format

### `SMB2_CREATE_CONTEXT` ([MS-SMB2] 2.2.13.2) — byte-offset table

All integers little-endian. Offsets are **relative to the start of *this* context**.

| Field        | Offset | Size | Notes |
|--------------|--------|------|-------|
| `Next`       | 0      | 4    | Bytes from start of this context to the next (8-byte-aligned) context. **0 = last context.** |
| `NameOffset` | 4      | 2    | Offset from start of this structure to the (8-byte-aligned) name. Conventionally `16`. |
| `NameLength` | 6      | 2    | Length in bytes of the name (4 for a 4CC). |
| `Reserved`   | 8      | 2    | MUST be 0 on send; ignored on receipt. |
| `DataOffset` | 10     | 2    | Offset from start of this structure to the (8-byte-aligned) data. `0` when `DataLength==0`. |
| `DataLength` | 12     | 4    | Length in bytes of the data payload (opaque here). |
| `Buffer`     | 16     | var  | Holds the name, then (8-byte-aligned) the data, per the offsets above. |

Fixed header = **16 bytes**, followed by the variable `Buffer`.

### Alignment / chaining rules (load-bearing)

1. **Name 8-byte alignment.** The name begins at the first 8-byte-aligned offset after the
   16-byte header. Since the header is itself 16 bytes and each context starts 8-byte
   aligned, the name lands at `NameOffset = 16` with no pad (16 is already a multiple of 8).
2. **Data 8-byte alignment.** The data begins at the first 8-byte-aligned offset after the
   name. For a 4-byte name (e.g. a 4CC): name occupies 16..19, so 4 pad bytes (20..23) bring
   `DataOffset = 24`. General rule: `DataOffset = align8(NameOffset + NameLength)`.
3. **Empty data.** If `DataLength == 0`, set `DataOffset = 0` and write no data bytes (no
   trailing pad required for the data region).
4. **Inter-context 8-byte alignment.** Each successive context MUST begin at the first
   8-byte-aligned offset after the end of the previous context's `Buffer`. The pad bytes
   between contexts are counted in the previous context's `Next` value.
5. **`Next` semantics.** `Next` on context *i* = (start of context *i+1*) − (start of
   context *i*), i.e. `align8(16 + namePad + nameLen + dataPad + dataLen)`. The **last**
   context has `Next = 0` and is **not** followed by trailing alignment padding.
6. **No ordering requirement.** Readers MUST accept contexts in any order; `readAll`
   preserves encounter order in the returned list.
7. **Outer offset.** Where this list sits in the enclosing CREATE message is fixed by the
   request/response's `CreateContexts{Offset,Length}` (handled in spec 03). `readAll` is
   told the absolute buffer `offset` and total `length` by the caller and seeks via `rpos`.

### `align8` helper (used throughout)

`align8(n) = (n + 7) & ~7` — round `n` up to the next multiple of 8. `padTo8(n) = align8(n) - n`.

## 4. Files to add / change

### Add

- `src/main/java/com/hierynomus/mssmb2/messages/create/SMB2CreateContext.java`
  (new package `com.hierynomus.mssmb2.messages.create`).
- `src/test/groovy/com/hierynomus/mssmb2/messages/create/SMB2CreateContextSpec.groovy`
  (new test package mirror).

### Change — deferred to spec 03 (listed here only as anchors; **do not edit in spec 01**)

In `src/main/java/com/hierynomus/mssmb2/messages/SMB2CreateRequest.java`, the create-context
backfill points are:

- **`SMB2CreateRequest.java:93`** — `buffer.putUInt32(0); // CreateContextsOffset (4 bytes)`
  → in spec 03, write the absolute offset of the context block (after the name, 8-byte
  aligned) or `0` when no contexts. Capture `buffer.wpos()` here to backfill.
- **`SMB2CreateRequest.java:94`** — `buffer.putUInt32(0); // CreateContextsLength (4 bytes)`
  → backfill with the total bytes written by `writeAll`. Capture this `wpos()` too.
- Context bytes themselves get appended after the name write at
  **`SMB2CreateRequest.java:96`** (`buffer.putRawBytes(nameBytes);`), 8-byte aligned, via
  `SMB2CreateContext.writeAll(buffer, contexts)`; then seek back with `wpos(savedPos)` to
  patch offset/length, mirroring the negotiate offset/length backfill pattern.

On the response side, **`SMB2CreateResponse.java:61-63`** currently reads and discards
`CreateContextsOffset`/`CreateContextsLength`. Spec 03 will instead capture them and call
`SMB2CreateContext.readAll(buffer, offset, length)`. Not touched in spec 01.

## 5. Class / method sketches

```java
package com.hierynomus.mssmb2.messages.create;

public class SMB2CreateContext {
    private final byte[] name;   // opaque; e.g. the 4CC "RqLs" (network-byte-order ASCII)
    private final byte[] data;   // opaque payload (may be empty, never null)

    public SMB2CreateContext(byte[] name, byte[] data);   // data defaults to new byte[0] if null

    public byte[] getName();
    public byte[] getData();

    // --- serialization ---------------------------------------------------

    /** Writes a chained list of contexts at the buffer's current wpos.
     *  Returns the total number of bytes written (0 for an empty/null list). */
    public static int writeAll(SMBBuffer buffer, List<SMB2CreateContext> contexts);

    /** Parses the chain starting at absolute buffer position {@code offset},
     *  bounded by {@code length} bytes. Returns contexts in encounter order
     *  (empty list when length == 0). */
    public static List<SMB2CreateContext> readAll(SMBBuffer buffer, int offset, int length)
        throws Buffer.BufferException;
}
```

### `writeAll` logic (pseudocode)

```
if contexts == null || contexts.isEmpty(): return 0
start = buffer.wpos()
for i in 0 .. contexts.size()-1:
    ctx        = contexts[i]
    isLast     = (i == contexts.size()-1)
    ctxStart   = buffer.wpos()
    nameLen    = ctx.name.length
    dataLen    = ctx.data.length
    nameOffset = 16                                  // header is 16, already 8-aligned
    dataOffset = (dataLen == 0) ? 0 : align8(nameOffset + nameLen)

    // header (16 bytes) — Next backfilled after we know the end
    nextPos = buffer.wpos()
    buffer.putUInt32(0)              // Next (placeholder)
    buffer.putUInt16(nameOffset)     // NameOffset
    buffer.putUInt16(nameLen)        // NameLength
    buffer.putReserved2()            // Reserved
    buffer.putUInt16(dataOffset)     // DataOffset (0 if no data)
    buffer.putUInt32(dataLen)        // DataLength

    buffer.putRawBytes(ctx.name)     // name at offset 16
    if dataLen > 0:
        pad = dataOffset - (nameOffset + nameLen)
        buffer.putReserved(pad)      // align data to 8
        buffer.putRawBytes(ctx.data)

    if not isLast:
        // pad the whole context up to an 8-byte boundary; Next spans the pad
        end       = buffer.wpos()
        ctxBytes  = end - ctxStart
        pad       = padTo8(ctxBytes)
        buffer.putReserved(pad)
        next      = ctxBytes + pad
        save = buffer.wpos(); buffer.wpos(nextPos);
        buffer.putUInt32(next); buffer.wpos(save)   // backfill Next
    // else: Next stays 0 (placeholder), no trailing pad

return buffer.wpos() - start
```

Notes:
- Use `wpos()`/`wpos(int)` to backfill `Next`, exactly as `SMB2NegotiateRequest` backfills
  the negotiate-context offset and as the negotiate template stitches via `putBuffer`.
- `nameOffset` is a constant 16 only because the header is 16 bytes; expressing it as
  `align8(16)` keeps the intent explicit.

### `readAll` logic (pseudocode)

```
result = new ArrayList()
if length == 0: return result
buffer.rpos(offset)
while true:
    ctxStart = buffer.rpos()
    next       = buffer.readUInt32AsInt()   // Next
    nameOffset = buffer.readUInt16()        // NameOffset
    nameLen    = buffer.readUInt16()        // NameLength
    buffer.skip(2)                          // Reserved
    dataOffset = buffer.readUInt16()        // DataOffset
    dataLen    = buffer.readUInt32AsInt()   // DataLength

    buffer.rpos(ctxStart + nameOffset)
    name = buffer.readRawBytes(nameLen)
    data = (dataLen > 0 && dataOffset != 0)
              ? (buffer.rpos(ctxStart + dataOffset), buffer.readRawBytes(dataLen))
              : new byte[0]
    result.add(new SMB2CreateContext(name, data))

    if next == 0: break
    buffer.rpos(ctxStart + next)            // jump to next 8-aligned context
return result
```

Notes:
- Seek by `ctxStart + NameOffset` / `ctxStart + DataOffset` rather than assuming layout, so
  any server ordering/padding is tolerated.
- `Next == 0` terminates the chain (last context); `length` bounds the block but the chain
  is authoritative, mirroring `SMB2NegotiateResponse.readNegotiateContextList`'s loop.

## 6. TDD tests (failing-first)

New Spock spec: `src/test/groovy/com/hierynomus/mssmb2/messages/create/SMB2CreateContextSpec.groovy`.
Style mirrors `SMB2CreateResponseSpec.groovy`: hex strings → `ByteArrayUtils.parseHex`,
byte-exact assertions. These do **not** go through `SMB2MessageConverter` (this layer isn't
a packet); they call the static codec directly against a fresh `SMBBuffer`. Write these
**before** the implementation — they must fail to compile/red first.

Shared constants for the tests (opaque names/data, deliberately lease-free):
- `name = "AbCd"` → ASCII bytes `41 62 43 64` (4 bytes).
- `dataA = 0x11 * 8` → eight `0x11` bytes (8-byte payload; already 8-aligned).
- A second context `name2 = "WxYz"` → `57 78 59 7a`, `dataB = 0x22 * 4` (4-byte payload).

### Worked byte example — two chained contexts with padding (the load-bearing test)

Encode `[ {AbCd, dataA(8B)}, {WxYz, dataB(4B)} ]`.

Context 0 (`{AbCd, 8×0x11}`):
```
Next       = 32  -> 20 00 00 00
NameOffset = 16  -> 10 00
NameLength = 4   -> 04 00
Reserved         -> 00 00
DataOffset = 24  -> 18 00
DataLength = 8   -> 08 00 00 00
name "AbCd"      -> 41 62 43 64            (offsets 16..19)
pad (20..23)     -> 00 00 00 00            (align data to 24)
data 8×0x11      -> 11 11 11 11 11 11 11 11 (offsets 24..31)
```
End of ctx0 = 32, already 8-aligned → no inter-context pad → `Next = 32`.

Context 1 (`{WxYz, 4×0x22}`, last):
```
Next       = 0   -> 00 00 00 00
NameOffset = 16  -> 10 00
NameLength = 4   -> 04 00
Reserved         -> 00 00
DataOffset = 24  -> 18 00
DataLength = 4   -> 04 00 00 00
name "WxYz"      -> 57 78 59 7a            (offsets 16..19)
pad (20..23)     -> 00 00 00 00
data 4×0x22      -> 22 22 22 22            (offsets 24..27)
```
Last context: `Next = 0`, **no** trailing pad. ctx1 length = 28. Total = 32 + 28 = 60 bytes.

Full expected hex (60 bytes):
```
20000000 1000 0400 0000 1800 08000000 41624364 00000000 1111111111111111
00000000 1000 0400 0000 1800 04000000 57785900            -- see note
```
Note: write the exact concatenation in the test as a single hex literal; the human-readable
split above is for review. The literal is:
`200000001000040000001800080000004162436400000000111111111111111100000000100004000000180004000000577859` + `7a22222222`.
(Implementers: assemble the literal in code from the field bytes above rather than
hand-transcribing, to avoid typos; the assertion is `buffer.getCompactData() == expected`.)

Test cases:

1. **`writeAll` two chained contexts with padding** — build the list above, call
   `writeAll(buf, list)`, assert `getCompactData()` equals the exact 60 bytes, and assert
   the returned count == 60. This pins `Next` chaining, the 4-byte name→data pad, and the
   absence of trailing pad on the last context.

2. **`readAll` round-trips the two-context bytes** — feed the same 60 bytes into a
   `SMBBuffer`, call `readAll(buf, 0, 60)`, assert: list size 2; element 0 name == `AbCd`
   bytes and data == eight `0x11`; element 1 name == `WxYz` bytes and data == four `0x22`.

3. **Round-trip property** — `readAll(writeAll(list))` yields a list equal to the original
   (compare names/data byte arrays). Guards against any asymmetry in offset math.

4. **Single context** — list of one `{AbCd, 8×0x11}`; `writeAll` produces exactly 32 bytes
   with `Next = 0` and no trailing pad; `readAll` returns one element with matching name/data.

5. **Empty data context** — `{AbCd, new byte[0]}`; assert `DataOffset` field == 0 and
   `DataLength` == 0 in the emitted bytes (header `... 00 00 / 00 00 00 00` at offsets 10
   and 12), no data/pad after the name; `readAll` returns `data.length == 0`.

6. **Empty list** — `writeAll(buf, [])` and `writeAll(buf, null)` both write 0 bytes and
   return 0; `getCompactData().length == 0`. `readAll(buf, 0, 0)` returns an empty list.

7. **Tolerates unaligned trailing block / extra length** — `readAll(buf, 0, 64)` over the
   60-byte two-context block (caller over-reports `length`) still returns exactly 2 contexts
   because `Next == 0` terminates the chain. Confirms `Next` is authoritative over `length`.

## 7. Acceptance criteria

- New package `com.hierynomus.mssmb2.messages.create` with `SMB2CreateContext` compiles
  (Java 8 target) and contains the static `writeAll` / `readAll` signatures in §5.
- `SMB2CreateContext` is **lease-agnostic**: no reference to `"RqLs"`, lease state/flags,
  V1/V2, or `DataLength`-based type inference anywhere in this class.
- `SMB2CreateContextSpec` exists, was red before implementation, and all seven test cases
  in §6 pass — including the byte-exact 60-byte two-context assertion and the empty-list /
  empty-data / single-context cases.
- Wire behavior matches §3: 16-byte header, `NameOffset = 16`, `DataOffset =
  align8(NameOffset + NameLength)` (or 0 when no data), `Next` spanning inter-context 8-byte
  padding, `Next = 0` with no trailing pad on the last context.
- No edits to `SMB2CreateRequest.java` / `SMB2CreateResponse.java` in this milestone (those
  backfill points are reserved for spec 03); the full existing `build` (incl.
  `SMB2CreateResponseSpec`) stays green.
