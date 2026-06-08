# 06 — Inbound Lease-Break Handling (receive → parse → epoch-check → invalidate → ack/close)

> Milestone 6 of `00-overview.md`. Builds on milestone 2 (`02-lease-model.md`:
> `LeaseKey`, `SMB2LeaseState`, `SMB2OplockLevel`) and milestone 5
> (`05-open-with-lease.md`: `LeaseManager` lease table, `register-before-send`,
> directory handle held open). Deliverable: route a **server-pushed** SMB2
> `OPLOCK_BREAK` (the unsolicited, all-FF `MessageId` form), parse the Lease-Break
> Notification (StructureSize 44), apply the epoch-delta staleness check, invalidate
> the associated directory cache (the `LeaseManager`/cache hook landed in 05/07), and —
> when an ack is required and the handle is not being closed — send a Lease-Break
> Acknowledgment (StructureSize 36) **off the receive thread**. Proven with offline
> byte-vector unit tests plus a live IT vs the .12 Samba.

---

## 1. Purpose & scope

Today smbj has **no route** for an unsolicited break. An async server push arrives with
`MessageId = 0xFFFFFFFFFFFFFFFF` and `Command = SMB2_OPLOCK_BREAK (0x12)`;
`SMB2IsOutstandingPacketHandler` already *tolerates* it (it does **not** dead-letter it —
see §4.2), but the very next handler, `SMB2AsyncResponsePacketHandler`, calls
`outstandingRequests.getRequestByMessageId(0xFFFF…FFFF)` which returns `null`, and then
dereferences it (`request.getTimestamp()`) → **NPE on the receive thread**
(`SMB2AsyncResponsePacketHandler.java:47-48`). Even if it survived that, the
`SMB2MessageConverter` switch has no `SMB2_OPLOCK_BREAK` case and **throws**
`SMBRuntimeException` (`SMB2MessageConverter.java:73-76`). So a break currently kills the
connection.

In scope (this milestone):

- **Break message models** (parse + build): `SMB2LeaseBreakNotification` (44),
  `SMB2OplockBreakNotification` (24, for completeness/non-lease oplocks),
  `SMB2LeaseBreakAcknowledgment` (36, client→server request build),
  `SMB2LeaseBreakResponse` (36, server→client parse).
- **`SMB2LeaseBreakPacketHandler`** — a new link inserted into the chain that recognizes an
  unsolicited break (all-FF `MessageId` + command `0x12`), parses by `StructureSize`,
  resolves the `LeaseKey` against the `LeaseManager`, applies the **epoch-delta** check
  (ignore stale/reordered), invalidates the directory cache (spec-07 hook), and — if
  `ACK_REQUIRED` and the handle is not being closed — schedules a Lease-Break ack
  **off the receive thread**. It **consumes** the packet (does not call `next.handle`),
  so the broken downstream path is never reached.
- **Threading:** the receive loop must never block on the ack round-trip (the ack is itself
  an SMB2 send that takes the connection lock and registers an outstanding request — sending
  it inline from the read thread risks a self-deadlock / stalls all other responses). The
  handler hands the break to the `LeaseManager` **off-thread** (via `SMBEventBus`-dispatched
  event consumed by a `LeaseManager`-owned single-thread executor, or a dedicated lease
  executor — see §5.5).

Out of scope: the cache data structure and its `list()` serving/invalidation semantics
(`07-directory-cache.md`); how the lease/handle got registered (`05`); negotiate gating
(`04`). This milestone only needs, from 05, a `LeaseManager` exposing
`lookup(LeaseKey)`, the held directory `Open`/handle, the stored `epoch`, and an
`invalidate(...)`/`close(...)` hook (§2). Where 05/07 are not yet merged, those are stubbed
(§2) so the unit tests stand alone.

---

## 2. Dependencies (02, 05; feeds 07)

From **milestone 02** (`com.hierynomus.mssmb2`):

```
LeaseKey                      // 16-byte value object, equals/hashCode -> Map key, .getBytes()
SMB2LeaseState               // bitmask helpers: isRead/isHandle/isReadHandle(long), READ_CACHING=0x1, HANDLE_CACHING=0x2
SMB2OplockLevel              // SMB2_OPLOCK_LEVEL_LEASE = 0xFF (not load-bearing here; FYI)
```

From **milestone 05** (`com.hierynomus.smbj.connection` / `share`), the lease table:

```java
public class LeaseManager {
    // registered at open-with-lease time (register-before-send, spec 05)
    LeasedDirectory lookup(LeaseKey key);          // null if unknown/stale registration
    // 06 calls these; their bodies land in 05/07:
    void onBreak(SMB2LeaseBreakNotification n);    // off-thread entry point (see §5.5)
}

public class LeasedDirectory {                     // the per-lease entry (05)
    LeaseKey getLeaseKey();
    int getEpoch();           void setEpoch(int e); // stored server epoch (V2)
    long getLeaseState();     void setLeaseState(long s);
    boolean isClosing();                            // handle is mid-close => implicit ack
    Session getSession();     long getTreeId();     // for sending the ack on the right session
    void invalidateCache();                         // spec-07 hook (bump generation / drop cache)
    void closeHandleAsync();                        // spec-05/07: close deferred dir handle (implicit ack)
}
```

> If 05 is not yet merged, the unit tests in §6 use a hand-rolled `LeaseManager` test double
> implementing `lookup`/`onBreak` and a `LeasedDirectory` stub; the **parse/build** specs do
> not need it at all (they exercise the message classes directly).

**Feeds milestone 07:** the cache invalidation in this handler is exactly the
`d_changecnt++` equivalent from Apple's model (`apple-smbclient-leases.md` §5). Spec 07
implements `invalidateCache()` so a subsequent `list()` re-fetches. This milestone only
**calls** the hook at the right moment (after the epoch check passes, before/around the ack).

---

## 3. Wire format

Command for **all** break messages: `SMB2_OPLOCK_BREAK = 0x0012`
(`SMB2MessageCommandCode.java`). The same command carries both oplock and lease breaks;
the **lease** form is distinguished by `StructureSize == 44` (oplock break = 24, ack/resp
= 36). All integers little-endian. Offsets below are **relative to the start of the SMB2
message body** (i.e. after the 64-byte SMB2 header).

### 3.1 The all-FF `MessageId` convention (how we recognize an unsolicited push)

Per [MS-SMB2] 3.2.5.1.2 (echoed in `SMB2AsyncResponsePacketHandler` javadoc and
`SMB2PacketData.isOplockBreakNotification()`, `SMB2PacketData.java:65`):

> If `MessageId == 0xFFFFFFFFFFFFFFFF`, this is **not** a reply to a previous request; the
> client MUST NOT look it up in `OutstandingRequests`. If the command is `SMB2_OPLOCK_BREAK`
> it is processed as a break; otherwise the response is discarded as invalid.

The notification header also has `SessionId = 0`, `TreeId = 0`, and SHOULD NOT be signed
(do **not** route it through signature verification expecting a session key — see §4.1 for
why insertion point matters). The discriminator we key on is exactly:

```
header.getMessageId() == 0xFFFFFFFFFFFFFFFFL  &&  header.getMessage() == SMB2_OPLOCK_BREAK
```

— i.e. the existing `SMB2PacketData.isOplockBreakNotification()` predicate.

### 3.2 Oplock-vs-lease disambiguation (StructureSize 44 lease vs 24 oplock)

Once we know it is an unsolicited `OPLOCK_BREAK`, read the first 2 bytes of the body
(`StructureSize`) **without** consuming intent, and branch:

| `StructureSize` | Body type | Class |
|-----------------|-----------|-------|
| **44** | Lease Break **Notification** | `SMB2LeaseBreakNotification` |
| **24** | Oplock Break **Notification** | `SMB2OplockBreakNotification` |
| **36** | Lease Break **Acknowledgment / Response** | `SMB2LeaseBreakResponse` (we only *receive* the 36-byte form as a response to our ack, which is *not* all-FF and goes the normal route — see §4.4) |

Only `44` matters for directory leases. `24` is parsed for completeness (logged + ignored
for now; file-oplock support is a non-goal, `00-overview.md`). Any other size on an all-FF
`OPLOCK_BREAK` → log + drop (malformed), never throw on the receive thread.

### 3.3 Lease Break **Notification** — `StructureSize 44` (server → client)

Source: [MS-SMB2] 2.2.23.2. Header: `Command=0x12`, `MessageId=0xFFFF…FFFF`,
`SessionId=0`, `TreeId=0`.

| Field              | Offset | Size | Notes |
|--------------------|--------|------|-------|
| `StructureSize`    | 0      | 2    | MUST be **44**. |
| `NewEpoch`         | 2      | 2    | uint16. SMB 3.x + V2 lease: `Lease.Epoch + 1`. 0 for SMB 2.1 / non-V2. |
| `Flags`            | 4      | 4    | `SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED = 0x01` when an ack is required. |
| `LeaseKey`         | 8      | 16   | identifies the lease (matches `LeaseManager` registration). |
| `CurrentLeaseState`| 24     | 4    | state **before** the break. |
| `NewLeaseState`    | 28     | 4    | target state (the ack's `LeaseState` MUST be a subset of this). |
| `BreakReason`      | 32     | 4    | reserved, 0 — ignore. |
| `AccessMaskHint`   | 36     | 4    | reserved, 0 — ignore. |
| `ShareMaskHint`    | 40     | 4    | reserved, 0 — ignore. |

**Total body = 44 bytes.**

### 3.4 Oplock Break **Notification** — `StructureSize 24` (parsed for completeness)

Source: [MS-SMB2] 2.2.23.1.

| Field           | Offset | Size | Notes |
|-----------------|--------|------|-------|
| `StructureSize` | 0      | 2    | MUST be **24**. |
| `OplockLevel`   | 2      | 1    | new oplock level (NONE/II/EXCLUSIVE/BATCH). |
| `Reserved`      | 3      | 1    | 0. |
| `Reserved2`     | 4      | 4    | 0. |
| `FileId`        | 8      | 16   | the open whose oplock broke. |

**Total = 24 bytes.** Not acted on this milestone (logged + dropped).

### 3.5 Lease Break **Acknowledgment** — `StructureSize 36` (client → server, request we BUILD)

Source: [MS-SMB2] 2.2.24.2. Sent **only** when the notification's `Flags` had
`ACK_REQUIRED (0x01)` **and** we did not implicitly ack by closing the handle.
Command `0x12`. `MessageId` is a **normal** (sequence-window) id — this is a real request we
get a response for. `SessionId`/`TreeId` are 0 per [MS-SMB2] 3.2.4.x (the break ack is not
tree-scoped; we send it on the connection — see §5.6).

| Field           | Offset | Size | Value |
|-----------------|--------|------|-------|
| `StructureSize` | 0      | 2    | MUST be **36**. |
| `Reserved`      | 2      | 2    | 0. |
| `Flags`         | 4      | 4    | reserved, 0. |
| `LeaseKey`      | 8      | 16   | same `LeaseKey` as the notification. |
| `LeaseState`    | 24     | 4    | the accepted (reduced) state — **MUST be a subset of the notification's `NewLeaseState`** (§3.6). |
| `LeaseDuration` | 28     | 8    | reserved, 0. |

**Total body = 36 bytes.**

### 3.6 ACK rules (when, and with what state)

Source: [MS-SMB2] 3.3.4.7 + `ms-smb2-lease-spec.md` §8d + `apple-smbclient-leases.md` §5.

- **No ack when** `Flags & ACK_REQUIRED == 0`. Per 3.3.4.7 the server sets `Flags=0`
  precisely when the current `Lease.LeaseState == R` only (a pure-read break is a one-way
  notification). We still invalidate the cache and update stored state/epoch; we **send
  nothing**.
- **Ack required when** `Flags & ACK_REQUIRED != 0` (the **RH directory** case: current
  state contains `H`, broken RH→R or RH→NONE). We must respond.
- **Implicit ack:** if we are closing the held directory handle (deferred close), the
  successful `CLOSE` **is** the ack ([MS-SMB2] 3.2.5.19.2 / Apple `skip_lease_break=1`).
  In that case do **not** also send an explicit ack. Decision: `LeasedDirectory.isClosing()`
  / the result of `closeHandleAsync()`.
- **Ack `LeaseState` value:** MUST be a **subset** of `NewLeaseState`. We acknowledge with
  exactly `NewLeaseState` (the server's target) — that is always a subset of itself and is
  what we are dropping to. (Apple acks "the new (reduced) lease state".) Concretely an RH
  directory broken to R acks `LeaseState = R (0x1)`; broken to NONE acks `0x0`.

### 3.7 Lease Break **Response** — `StructureSize 36` (server → client, parsed)

Source: [MS-SMB2] 2.2.25.2. Same 36-byte layout as the ack
(`StructureSize=36`, `Reserved(2)=0`, `Flags(4)=0`, `LeaseKey(16)`,
`LeaseState(4)` = final granted state, `LeaseDuration(8)=0`). This arrives as a **normal
reply** to our ack request (its `MessageId` matches the ack we sent, **not** all-FF), so it
flows through the existing chain → `SMB2MessageConverter` → `SMB2ProcessResponsePacketHandler`
and delivers to the ack request's promise. The converter therefore needs an
`SMB2_OPLOCK_BREAK` case (§4.4).

### 3.8 Epoch-delta staleness check

Source: `apple-smbclient-leases.md` §4 (`smbfs_get_epoch_delta`). V2 leases carry a uint16
`NewEpoch = storedEpoch + 1` per state change. Compute `delta = epochDelta(newEpoch,
storedEpoch)`:

```
if newEpoch == storedEpoch        -> 0   (no change; ignore the break)
if newEpoch  > storedEpoch        -> newEpoch - storedEpoch          (apply)
if storedEpoch > newEpoch and (storedEpoch - newEpoch) > 32767 -> wrap: server newer (apply)
otherwise (storedEpoch > newEpoch within window)               -> -1 (stale/reordered: ignore)
```

- `delta <= 0` → **ignore** the break entirely (do not invalidate, do not ack). This is the
  reordered/stale guard.
- `delta >= 1` → **apply**: invalidate cache, update stored `epoch = newEpoch` and
  `leaseState = NewLeaseState`, then ack/close per §3.6.
- **`NewEpoch == 0`** (SMB 2.1 / non-V2, no epoch ordering): treat as `delta = 1` (always
  apply) — matches Apple's "LeaseV1 ⇒ assume delta_epoch=1". Directory leases are always V2,
  so for dir leases `NewEpoch` is non-zero in practice.

---

## 4. Files to add / change — exact `file:line` anchors

### 4.1 Chain insertion in `Connection.init()` — `connection/Connection.java:121-128`

The chain today (verbatim, `:121-128`):

```java
this.packetHandlerChain = new SMB3DecryptingPacketHandler(sessionTable, encryptor).setNext(
    new SMB2CompoundedPacketHandler().setNext(
        new SMB2IsOutstandingPacketHandler(outstandingRequests).setNext(
            new SMB2SignatureVerificationPacketHandler(sessionTable, signatory).setNext(
                new SMB2CreditGrantingPacketHandler(sequenceWindow).setNext(
                    new SMB2AsyncResponsePacketHandler(outstandingRequests).setNext(
                        new SMB2ProcessResponsePacketHandler(messageConverter, outstandingRequests).setNext(
                            new SMB1PacketHandler().setNext(new DeadLetterPacketHandler()))))))));
```

**Insert `SMB2LeaseBreakPacketHandler` immediately after `SMB2IsOutstandingPacketHandler`
and before `SMB2SignatureVerificationPacketHandler`** (i.e. between `:123` and `:124`).
Rationale:

- It must be **after** `SMB2IsOutstandingPacketHandler` (`:123`), which is the link that
  recognizes the all-FF break and **passes it through** instead of dead-lettering it
  (`SMB2IsOutstandingPacketHandler.java:50` — `!isOplockBreakNotification()` guards the
  dead-letter branch, so a break falls into the `else { next.handle(packetData); }` at
  `:53-54`).
- It must be **before** `SMB2SignatureVerificationPacketHandler` (`:124`) and
  `SMB2AsyncResponsePacketHandler` (`:126`): the break has `SessionId=0` and is unsigned, so
  running it through signature verification is wrong, and `SMB2AsyncResponsePacketHandler`
  is exactly where the **NPE** occurs (`:47-48`, `getRequestByMessageId(allFF)==null`).
  By **consuming** the packet (not calling `next.handle`) for a genuine unsolicited break,
  our handler short-circuits both.
- Non-break packets (every normal response, and our own ack's 36-byte response, which has a
  real `MessageId`) **fail** the all-FF+0x12 predicate and are passed straight through via
  `next.handle(packetData)` — so async/compound/credit/signature handling for everything
  else is untouched.

New chain (the one inserted line shown):

```java
new SMB2IsOutstandingPacketHandler(outstandingRequests).setNext(
    new SMB2LeaseBreakPacketHandler(leaseManager, leaseBreakExecutor).setNext(   // <-- NEW
        new SMB2SignatureVerificationPacketHandler(sessionTable, signatory).setNext(
            ...
```

The `leaseManager` and `leaseBreakExecutor` are constructed in `init()` (see §5.5); the
`LeaseManager` itself is created in milestone 05 and held as a `Connection` field — this
milestone wires it into the handler ctor.

### 4.2 `SMB2IsOutstandingPacketHandler` — no change (confirm pass-through)

`connection/packet/SMB2IsOutstandingPacketHandler.java:50-55` already lets a break through
unchanged. **Do not modify.** (Documenting it so the insertion contract is explicit.)

### 4.3 New handler — `connection/packet/SMB2LeaseBreakPacketHandler.java` (add)

Extends `SMB2PacketHandler` (`connection/packet/SMB2PacketHandler.java:23`), so it inherits
`canHandle(instanceof SMB2PacketData)` and the `doSMB2Handle` template
(`AbstractIncomingPacketHandler` runs `canHandle` then `doHandle`). Follows the same
`setNext`/`next` shape as every sibling (`IncomingPacketHandler.java:30`). See §5.

### 4.4 Converter / factory registration — `mssmb2/SMB2MessageConverter.java:73-76`

Replace the throwing `SMB2_OPLOCK_BREAK` fall-through. Today:

```java
case SMB2_OPLOCK_BREAK:
default:
    logger.error("Unknown SMB2 Message Command type: " + command);
    throw new SMBRuntimeException("Unknown SMB2 Message Command type: " + command);
```

Change to give `SMB2_OPLOCK_BREAK` its own case returning a break packet **disambiguated by
StructureSize** (so the 36-byte response to our own ack parses correctly via the normal
`SMB2ProcessResponsePacketHandler` route — §3.7), leaving `default:` to throw:

```java
case SMB2_OPLOCK_BREAK:
    return SMB2BreakMessage.forStructureSize(packetData);   // 44->Notification, 24->Oplock, 36->Response
default:
    logger.error(...); throw new SMBRuntimeException(...);
```

`forStructureSize(...)` peeks `StructureSize` (next 2 bytes of the body, via a
non-consuming read on a duplicated buffer, mirroring how `SMB2PacketData` exposes the body)
and returns the right `SMB2Packet` subclass. **Note:** the notification (all-FF) is consumed
by `SMB2LeaseBreakPacketHandler` and never reaches the converter on the response path; the
converter case exists mainly for the **36-byte response** to our ack and for any oplock
break that some future code routes through the normal path. The break handler parses the
notification itself (§5.2) directly from `SMB2PacketData` rather than via the converter, to
avoid needing a matching outstanding request.

### 4.5 New message classes — `mssmb2/messages/` (add)

```
smbj/src/main/java/com/hierynomus/mssmb2/messages/SMB2LeaseBreakNotification.java   // parse 44
smbj/src/main/java/com/hierynomus/mssmb2/messages/SMB2OplockBreakNotification.java  // parse 24
smbj/src/main/java/com/hierynomus/mssmb2/messages/SMB2LeaseBreakAcknowledgment.java // build 36 (request)
smbj/src/main/java/com/hierynomus/mssmb2/messages/SMB2LeaseBreakResponse.java       // parse 36
```

All extend `SMB2Packet` (`mssmb2/SMB2Packet.java:25`), reading via `readMessage(SMBBuffer)`
and (for the ack) writing via `writeTo(SMBBuffer)`, exactly like `SMB2Close`
(`messages/SMB2Close.java:50-70`). The new `SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED`
constant (0x01) lives on `SMB2LeaseBreakNotification` (or a small enum alongside the
milestone-02 lease enums — keep it where 02's `SMB2LeaseFlags` live if convenient, but it is
a *notification* flag, distinct from create-context lease flags).

### 4.6 Send-ack path — `connection/Connection.java:216` (`send`) / Session.send

The ack is built as `SMB2LeaseBreakAcknowledgment` and sent through the **normal**
`Connection.send(SMB2Packet)` (`Connection.java:216`) — it must get a real sequence-window
`MessageId` and be registered in `outstandingRequests` so the 36-byte response is matched.
It is sent on the session that owns the leased open (`LeasedDirectory.getSession().send(...)`
so signing applies), **never** from the receive thread (§5.5/§5.6). The response future may
be observed for logging/verification but the receive loop does not wait on it.

### 4.7 (Optional) `SMB2PacketData` helper — `mssmb2/SMB2PacketData.java:65`

`isOplockBreakNotification()` already exists and is reused by the handler. If a
StructureSize peek helper is wanted on `SMB2PacketData`, add `int peekStructureSize()` near
`:65`; otherwise the handler peeks via the data buffer. No change strictly required.

---

## 5. Class / method sketches

> Signatures + key logic only. Use `SMBBuffer` (`putUInt16/putUInt32/putReserved/
> putRawBytes/readUInt16/readUInt32/readRawBytes/skip`) exactly as `SMB2Close`. Enums via
> `EnumWithValue` as in milestone 02. Nothing here blocks the read thread on I/O.

### 5.1 `SMB2LeaseBreakNotification` (parse 44)

```java
public class SMB2LeaseBreakNotification extends SMB2Packet {
    public static final long SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED = 0x01L;

    private int newEpoch;                 // uint16
    private long flags;                   // uint32
    private LeaseKey leaseKey;            // 16
    private long currentLeaseState;       // uint32 bitmask
    private long newLeaseState;           // uint32 bitmask

    public SMB2LeaseBreakNotification() {}            // for converter / factory

    @Override protected void readMessage(SMBBuffer b) throws Buffer.BufferException {
        int structureSize = b.readUInt16();           // MUST be 44
        if (structureSize != 44) throw new IllegalStateException("Not a lease break: " + structureSize);
        newEpoch          = b.readUInt16();           // NewEpoch
        flags             = b.readUInt32();           // Flags
        leaseKey          = new LeaseKey(b.readRawBytes(16));
        currentLeaseState = b.readUInt32();
        newLeaseState     = b.readUInt32();
        b.skip(12);                                   // BreakReason + AccessMaskHint + ShareMaskHint
    }

    public boolean isAckRequired() {
        return (flags & SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED) != 0;
    }
    public int getNewEpoch();           public LeaseKey getLeaseKey();
    public long getCurrentLeaseState(); public long getNewLeaseState();
}
```

### 5.2 `SMB2OplockBreakNotification` (parse 24) — minimal

```java
public class SMB2OplockBreakNotification extends SMB2Packet {
    private int oplockLevel;  private SMB2FileId fileId;
    @Override protected void readMessage(SMBBuffer b) throws Buffer.BufferException {
        b.readUInt16();                  // StructureSize == 24
        oplockLevel = b.readByte() & 0xFF;
        b.skip(1); b.skip(4);            // Reserved + Reserved2
        fileId = SMB2FileId.read(b);     // 16
    }
}
```

### 5.3 `SMB2LeaseBreakAcknowledgment` (build 36, request)

```java
public class SMB2LeaseBreakAcknowledgment extends SMB2Packet {
    private final LeaseKey leaseKey;
    private final long leaseState;       // subset of notification.NewLeaseState

    public SMB2LeaseBreakAcknowledgment(SMB2Dialect dialect, long sessionId, long treeId,
                                        LeaseKey leaseKey, long leaseState) {
        super(36, dialect, SMB2MessageCommandCode.SMB2_OPLOCK_BREAK, sessionId, treeId); // sessionId/treeId = 0 per spec
        this.leaseKey = leaseKey; this.leaseState = leaseState;
    }

    @Override protected void writeTo(SMBBuffer b) {
        b.putUInt16(structureSize);      // 36
        b.putReserved2();                // Reserved
        b.putReserved4();                // Flags = 0
        b.putRawBytes(leaseKey.getBytes()); // 16
        b.putUInt32(leaseState);         // accepted (reduced) state
        b.putReserved(8);                // LeaseDuration = 0
    }
}
```

### 5.4 `SMB2LeaseBreakResponse` (parse 36)

```java
public class SMB2LeaseBreakResponse extends SMB2Packet {
    private LeaseKey leaseKey; private long leaseState;
    @Override protected void readMessage(SMBBuffer b) throws Buffer.BufferException {
        b.readUInt16();                  // StructureSize == 36
        b.skip(2);                       // Reserved
        b.skip(4);                       // Flags
        leaseKey   = new LeaseKey(b.readRawBytes(16));
        leaseState = b.readUInt32();     // final granted state
        b.skip(8);                       // LeaseDuration
    }
    public LeaseKey getLeaseKey(); public long getLeaseState();
}
```

### 5.5 `SMB2LeaseBreakPacketHandler` — `handle()` logic + threading

```java
public class SMB2LeaseBreakPacketHandler extends SMB2PacketHandler {
    private static final Logger logger = ...;
    private final LeaseManager leaseManager;
    private final Executor leaseBreakExecutor;   // dedicated single-thread executor (NOT the read thread)

    public SMB2LeaseBreakPacketHandler(LeaseManager leaseManager, Executor leaseBreakExecutor) { ... }

    @Override
    protected void doSMB2Handle(SMB2PacketData packetData) throws TransportException {
        // 1. Only intercept a genuine UNSOLICITED break (all-FF MessageId + 0x12).
        if (!packetData.isOplockBreakNotification()) {     // SMB2PacketData.java:65
            next.handle(packetData);                       // everything else (incl. our ack's response) flows on
            return;
        }
        // 2. Disambiguate by StructureSize (44 lease / 24 oplock / other) -- §3.2.
        int structureSize = peekStructureSize(packetData); // non-consuming peek of body[0..1]
        if (structureSize != 44) {
            if (structureSize == 24) logger.debug("Oplock break (24) received, ignoring (file oplocks out of scope)");
            else logger.warn("Unexpected unsolicited OPLOCK_BREAK StructureSize {} -- dropping", structureSize);
            return;                                         // CONSUME: do not call next (avoids NPE downstream)
        }
        // 3. Parse the 44-byte notification right here (no outstanding request exists for it).
        SMB2LeaseBreakNotification n;
        try { n = parseNotification(packetData); }          // builds SMB2LeaseBreakNotification via readMessage
        catch (Buffer.BufferException e) { logger.warn("Malformed lease break, dropping", e); return; }

        logger.debug("Lease break for key {} {}->{} ackReq={}",
            n.getLeaseKey(), n.getCurrentLeaseState(), n.getNewLeaseState(), n.isAckRequired());

        // 4. Hand off OFF the receive thread. The read loop returns immediately.
        //    onBreak() does: lookup, epoch-check, invalidate, ack/close (§5.6).
        leaseBreakExecutor.execute(() -> {
            try { leaseManager.onBreak(n); }
            catch (Throwable t) { logger.error("Lease-break handling failed for {}", n.getLeaseKey(), t); }
        });
        // CONSUME: never call next.handle(...) for the notification.
    }
}
```

**Threading rationale (load-bearing):** `doSMB2Handle` runs on the transport **read thread**.
Sending the ack calls `Connection.send` → takes the connection `lock`
(`Connection.java:220`), draws a credit from the `sequenceWindow`, registers an outstanding
request, and writes to the transport — and we then await the 36-byte response, **which can
only arrive on this same read thread**. Doing that inline would deadlock / stall every other
response. So the handler does the cheap, non-blocking work (recognize + parse + log) inline
and **dispatches the resolve/invalidate/ack** to `leaseBreakExecutor`, a dedicated
single-thread executor owned by the `Connection`/`LeaseManager` (constructed in
`Connection.init()`, shut down in `Connection.close`). The cache invalidation itself (a
generation-counter bump, spec 07) is cheap and could run inline, but to keep ordering simple
**all** of `onBreak` runs on the executor.

> **Alternative dispatch via `SMBEventBus`:** the existing bus is a **synchronous**
> `SyncMessageBus` (`SMBEventBus.java:35`), so publishing on it runs subscribers on the
> caller (read) thread — that would *not* get us off-thread. Therefore use the dedicated
> executor for the off-thread hand-off; the `SMBEventBus` may still be used to *notify*
> application listeners of a `LeaseBroken` event (fire-and-forget) **from inside the executor
> task**, not for the ack send. (This mirrors how `Connection` already publishes
> `ConnectionClosed`/`SessionLoggedOff`, `Connection.java:191`.)

### 5.6 `LeaseManager.onBreak(...)` — resolve → epoch → invalidate → ack/close (runs on executor)

```java
void onBreak(SMB2LeaseBreakNotification n) throws TransportException {
    LeasedDirectory ld = lookup(n.getLeaseKey());      // §2; null => unknown/stale
    if (ld == null) { logger.debug("Break for unknown lease key {}, ignoring", n.getLeaseKey()); return; }

    // Epoch-delta staleness check -- §3.8.
    int delta = epochDelta(n.getNewEpoch(), ld.getEpoch());
    if (n.getNewEpoch() != 0 && delta <= 0) {          // V2 stale/reordered => ignore entirely
        logger.debug("Stale lease break (newEpoch {} <= stored {}), ignoring", n.getNewEpoch(), ld.getEpoch());
        return;
    }

    // Apply: invalidate cache + update stored state/epoch (spec 07 hook).
    ld.invalidateCache();                              // d_changecnt++ equivalent
    ld.setLeaseState(n.getNewLeaseState());
    if (n.getNewEpoch() != 0) ld.setEpoch(n.getNewEpoch());

    // Ack policy -- §3.6.
    boolean handleClosed = false;
    if (!SMB2LeaseState.isHandle(n.getNewLeaseState()) || ld.isClosing()) {
        // Losing H (or already deferring close): closing the dir handle is an IMPLICIT ack.
        handleClosed = ld.closeHandleAsync();          // returns true if a CLOSE was issued
    }
    if (n.isAckRequired() && !handleClosed) {
        SMB2LeaseBreakAcknowledgment ack = new SMB2LeaseBreakAcknowledgment(
            ld.getSession().getDialect(), 0L, 0L,      // SessionId/TreeId = 0 (§3.5)
            n.getLeaseKey(), n.getNewLeaseState());    // LeaseState subset of NewLeaseState (§3.6)
        Future<SMB2LeaseBreakResponse> f = ld.getSession().send(ack); // normal send path (§4.6)
        // do not block the executor on f beyond an optional logged get with timeout
    }
}

// epochDelta exactly as §3.8 (handles ==, >, wrap, stale).
static int epochDelta(int newEpoch, int storedEpoch);
```

> `closeHandleAsync()` and `invalidateCache()` bodies are spec 05/07. Whether to close vs ack
> for a dir lease: a directory broken **RH→R** keeps `R` (still read-cacheable) and is acked
> with `R` without closing; a break **to NONE** (loses H, no read) closes the deferred handle
> (implicit ack) — matching Apple `need_close_dir`. The `isHandle(newLeaseState)` test above
> encodes "we still hold H → ack-and-keep; we lost H → close".

---

## 6. TDD tests (failing-first)

Unit specs are offline byte-vector tests (Spock, mirroring
`AbstractPacketReadSpec`/`SMB2CreateResponseSpec`). Write red first.

### 6.1 `SMB2LeaseBreakNotificationSpec` — parse a captured 44-byte notification

`src/test/groovy/com/hierynomus/mssmb2/messages/SMB2LeaseBreakNotificationSpec.groovy`.
Feed a full SMB2 message (64-byte header with `Command=0x12`, `MessageId=FF*8`,
`SessionId=0`, `TreeId=0`) + this 44-byte body and assert parsed fields:

```
2C 00            StructureSize = 44
06 00            NewEpoch = 6
01 00 00 00      Flags = ACK_REQUIRED
000102030405060708090A0B0C0D0E0F   LeaseKey
03 00 00 00      CurrentLeaseState = RH (0x3)
01 00 00 00      NewLeaseState     = R  (0x1)
00 00 00 00      BreakReason
00 00 00 00      AccessMaskHint
00 00 00 00      ShareMaskHint
```

Assert: `getNewEpoch()==6`, `isAckRequired()==true`,
`getLeaseKey()==LeaseKey(0001..0F)`, `getCurrentLeaseState()==0x3`,
`getNewLeaseState()==0x1`. Add a second vector with `Flags=00 00 00 00` →
`isAckRequired()==false` (the pure-R no-ack case). Add a `StructureSize != 44` vector →
parse throws / is rejected (the disambiguation guard).

### 6.2 `SMB2LeaseBreakAcknowledgmentSpec` — build → assert 36 bytes

`...messages/SMB2LeaseBreakAcknowledgmentSpec.groovy`. Build
`new SMB2LeaseBreakAcknowledgment(SMB_3_1_1, 0, 0, LeaseKey(0001..0F), R=0x1)`, write the
**body** (via `writeTo` into an `SMBBuffer`) and assert exactly **36** bytes:

```
24 00            StructureSize = 36
00 00            Reserved
00 00 00 00      Flags = 0
000102030405060708090A0B0C0D0E0F   LeaseKey
01 00 00 00      LeaseState = R (subset of NewLeaseState)
00 00 00 00 00 00 00 00   LeaseDuration = 0
```

Also assert the header `Command == SMB2_OPLOCK_BREAK (0x12)` and `SessionId==0`,
`TreeId==0`. Add a subset-rule assertion at the `onBreak` level (6.4): the acked
`LeaseState` equals `NewLeaseState` and `(ackState & ~newLeaseState) == 0`.

### 6.3 `SMB2LeaseBreakResponseSpec` — parse 36-byte response

Feed a 36-byte response body (StructureSize 36, `LeaseKey`, `LeaseState = R`) → assert
`getLeaseKey()`/`getLeaseState()`. Confirms the converter's `SMB2_OPLOCK_BREAK` case parses
the reply to our ack (§3.7).

### 6.4 `LeaseManagerBreakSpec` — epoch-stale is ignored; ack/invalidate fire

`src/test/groovy/com/hierynomus/smbj/connection/LeaseManagerBreakSpec.groovy`, using a
`LeasedDirectory` test double (records `invalidateCache`/`setLeaseState`/`setEpoch`/sent ack).

- **Stale ignored:** stored epoch = 6; deliver notification `NewEpoch=6` (delta 0) and
  `NewEpoch=5` (delta −1) → `invalidateCache` **not** called, no ack sent, stored state
  unchanged.
- **Newer applied:** stored epoch = 6; `NewEpoch=7`, RH→R, `ACK_REQUIRED` → `invalidateCache`
  called once, `setLeaseState(0x1)`, `setEpoch(7)`, and an `SMB2LeaseBreakAcknowledgment` with
  `leaseState==0x1` is produced (assert subset of `NewLeaseState`).
- **No-ack break:** `Flags=0` (pure R) → cache invalidated, **no** ack sent.
- **Implicit ack on close:** break to NONE (loses H) → `closeHandleAsync()` invoked and **no**
  explicit ack sent even though `ACK_REQUIRED` (closing = implicit ack).
- **Off-thread:** assert `onBreak` is dispatched via the executor, not run on the calling
  (read) thread — e.g. the handler returns before the (latched) executor task completes.
- **Unknown key:** `lookup` returns null → no throw, nothing sent.

### 6.5 `SMB2LeaseBreakChainSpec` — handler consumes the break; no NPE

Drive `SMB2LeaseBreakPacketHandler` with a stub `next` that fails the test if called, plus a
real all-FF 44-byte break `SMB2PacketData`. Assert: `next` is **not** invoked, the executor
receives one task, and a normal (non-break) `SMB2PacketData` **is** forwarded to `next`. This
is the regression test for the current `SMB2AsyncResponsePacketHandler` NPE
(`:47-48`) and the converter throw (`:73-76`).

### 6.6 Integration (live, vs `<smb-host>:1445`, share `testshare`) — failing-first

`src/it/.../DirectoryLeaseBreakIntegrationTest` (gated on
`connectionContext.supportsDirectoryLeasing()`; skip otherwise). Flow:

1. Connection **A**: open `testshare` root (or a subdir) **with an RH directory lease**
   (milestone 05). Assert granted state includes `H` and a lease was registered.
2. From a **second connection B** (a separate smbj `Connection`/`Session` to the same share)
   — or out-of-band via `ssh`/`smbclient` on the .12 host — **mutate** the directory:
   create/delete/rename a child entry (e.g. `mkdir break-probe-<rand>`). This is what causes
   the server to break A's parent directory lease via the `ParentLeaseKey` linkage.
3. **Assert on A:** within a timeout (e.g. 5 s) the break is received and handled — the
   handler did **not** throw / the connection stays alive; the registered lease state drops
   (RH→R or →NONE); if `ACK_REQUIRED`, a `SMB2LeaseBreakAcknowledgment` was sent and a
   36-byte `SMB2LeaseBreakResponse` received (observe via a test hook / counter on
   `LeaseManager`). Use a latch the executor task counts down.
4. **Feeds 07:** assert the directory cache generation was bumped (a subsequent `list()`
   re-queries the server rather than serving stale entries) — the full cache-serving
   assertion lands in milestone 07, but the invalidation hook is exercised here.

This IT **fails before** the milestone (today: NPE on the receive thread / connection torn
down on the first break) and **passes after**. Mark it `@Requires` directory-leasing so it
no-ops against a lease-unaware server.

---

## 7. Acceptance criteria

1. `SMB2LeaseBreakNotification` parses a 44-byte body to
   `{newEpoch, flags/isAckRequired, leaseKey, currentLeaseState, newLeaseState}` byte-exactly
   (§6.1); rejects non-44 `StructureSize`.
2. `SMB2LeaseBreakAcknowledgment` writes the **exact 36** bytes of §6.2 with `Command=0x12`,
   `SessionId=0`, `TreeId=0`, and `LeaseState` a **subset** of the notification's
   `NewLeaseState`; `SMB2LeaseBreakResponse` parses the 36-byte reply.
3. `SMB2MessageConverter` (`:73-76`) no longer throws on `SMB2_OPLOCK_BREAK`; it returns the
   StructureSize-appropriate class (44/24/36). `default:` still throws.
4. `SMB2LeaseBreakPacketHandler` is inserted **between `SMB2IsOutstandingPacketHandler`
   (`Connection.java:123`) and `SMB2SignatureVerificationPacketHandler` (`:124`)**; it
   **consumes** a genuine all-FF `0x12` break (never calls `next`), and **forwards** every
   other packet unchanged. The previous receive-thread **NPE** in
   `SMB2AsyncResponsePacketHandler` (`:47-48`) is no longer reachable for a break.
5. The epoch-delta check (§3.8) **ignores** `delta <= 0` (stale/reordered) breaks — no
   invalidate, no ack — and **applies** `delta >= 1` (and `NewEpoch==0` non-V2) breaks
   (`LeaseManagerBreakSpec`, §6.4).
6. On an applied break the directory **cache is invalidated** (spec-07 hook called),
   stored `leaseState`/`epoch` updated, and: (a) if `ACK_REQUIRED` and the handle is **not**
   closed → exactly one `SMB2LeaseBreakAcknowledgment` is sent via the **normal send path**
   on the owning session; (b) if the handle is closed → **no** explicit ack (implicit ack via
   `CLOSE`); (c) if `ACK_REQUIRED` is clear → **no** ack.
7. **Threading:** the ack/resolve runs on a **dedicated executor**, never the transport read
   thread; the read loop returns immediately after dispatch. The `SyncMessageBus` is **not**
   used for the off-thread hand-off. No deadlock; existing async/compound/credit/signature
   handling for non-break traffic is unchanged.
8. Live IT (§6.6) vs `.12 testshare`: an external directory mutation breaks the held RH lease;
   the client receives + (if required) acks the break, the lease state drops, and the cache
   generation is bumped — IT was red (NPE/connection drop) before, green after. All offline
   unit specs and the existing `build` suite stay green.
