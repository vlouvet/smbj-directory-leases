# smbj Directory-Lease Support — Code Map / Change-Point Analysis

All paths are relative to `smbj/src/main/java/` unless noted. Line numbers are from the
current checkout. This document is a read-only analysis; no smbj source was modified.

Key up-front findings:

- The infrastructure is **further along than expected**. The command code
  `SMB2_OPLOCK_BREAK` exists, capability flags `SMB2_GLOBAL_CAP_LEASING` /
  `SMB2_GLOBAL_CAP_DIRECTORY_LEASING` exist, `ConnectionContext.supportsDirectoryLeasing()`
  / `supportsFileLeasing()` exist, dialects include SMB 3.1.1, and
  `SMB2PacketData.isOplockBreakNotification()` already detects a server-pushed break.
- But there is **no functional path** end-to-end: create contexts are never serialized,
  lease caps are never advertised, oplock/lease-break packets are recognized but then
  fall through to a handler that throws, there is no create-context model, no lease model,
  no lease-break ack, and no directory caching.

---

## 1. SMB2 CREATE request/response path

### 1.1 Request — `com/hierynomus/mssmb2/messages/SMB2CreateRequest.java`

- `writeTo(SMBBuffer)` at **line 62**.
  - **RequestedOplockLevel** is hardcoded to `0` (None) at **line 65**:
    `buffer.putByte((byte) 0); // RequestedOpLockLevel (1 byte) - None`.
    For leasing this must become `SMB2_OPLOCK_LEVEL_LEASE = 0xFF`.
  - **CreateContextsOffset / CreateContextsLength** are both hardcoded `0` at
    **lines 93–94**:
    ```
    buffer.putUInt32(0); // CreateContextsOffset (4 bytes)
    buffer.putUInt32(0); // CreateContextsLength (4 bytes)
    ```
  - **Name layout:** `offset` (line 74) = `SMB2PacketHeader.STRUCTURE_SIZE (64) +
    structureSize (57) - 1` = 120, i.e. the name immediately follows the 56-byte
    fixed body. NameOffset/NameLength are written at lines 80–81 / 88–89. The raw
    name bytes are written **last**, at **line 96** (`buffer.putRawBytes(nameBytes)`).
  - **Where create contexts must be serialized:** create contexts come *after* the
    name in the buffer (the name is variable-length and precedes the contexts).
    The serialization must:
    1. Write the name (current line 96).
    2. 8-byte align the buffer write position (`buffer.wpos()`), padding with
       `buffer.putReserved(...)`, because each create-context entry must start on an
       8-byte boundary ([MS-SMB2] 2.2.13.2 — every `SMB2_CREATE_CONTEXT` is 8-byte aligned).
    3. Capture the aligned position; that absolute offset is `CreateContextsOffset`
       (relative to the start of the SMB2 *header*, i.e. `wpos - header.getHeaderStartPosition()`).
    4. Write each context with the chaining `Next` field: `Next` = byte length from the
       start of this context to the start of the next context (including inter-context
       padding), or `0` for the last context.
    5. Total bytes written = `CreateContextsLength`.
    - Because offset/length are written *before* the name (lines 93–94) but the actual
      bytes are written *after*, the cleanest implementation writes the contexts into a
      temp `SMBBuffer` first to compute offset+length, then back-patches. Compare the
      existing back-patch pattern below.
  - **Model to copy — Negotiate context serialization.** `SMB2NegotiateRequest.writeTo`
    (messages/SMB2NegotiateRequest.java lines 77–91, helpers 101–130) already implements
    the identical "offset + 8-byte alignment + chained variable-length contexts" pattern
    for negotiate contexts, including computing an aligned offset (lines 86–89, 119–123)
    and per-context 8-byte padding between entries (lines 101–111). This is the single
    best template for the create-context writer.
  - `SMBBuffer.putReserved(int)` (smb/SMBBuffer.java line 42) is the padding primitive;
    `Buffer.wpos()` (protocol/commons/buffer/Buffer.java line 162) gives the current write
    position; `Buffer.putBuffer(...)` (line 342) appends a temp buffer.
  - Constructor (lines 44–59) currently takes no oplock/lease/context params. A new
    constructor (or overload) must accept a `requestedOplockLevel` byte and a
    `List<SMB2CreateContextRequest>` (or a lease object), so `Share.createFile` can pass them.

### 1.2 Response — `com/hierynomus/mssmb2/messages/SMB2CreateResponse.java`

- `readMessage(SMBBuffer)` at **line 46**.
  - **OplockLevel** is read but discarded at **line 48**: `buffer.readByte(); // OpLockLevel
    (1 byte) - Not used yet`. Must be captured into a field for lease responses.
  - **Flags** read but discarded at **line 49** (`// Flags (1 byte) - Only for 3.x`).
    For directory leasing the response Flags byte carries
    `SMB2_CREATE_FLAG_REPARSEPOINT` and is otherwise reserved; the lease grant itself
    comes back in a create context, not these flags.
  - **Create contexts are explicitly ignored** at **lines 61–63**:
    ```
    // Ignore create contexts and the buffer.
    buffer.readUInt32();// CreateContextsOffset (4 bytes)
    buffer.readUInt32();// CreateContextsLength (4 bytes)
    ```
  - **Where lease-response parsing hooks in:** replace lines 61–63 to capture
    `createContextsOffset` and `createContextsLength`; if length > 0, `buffer.rpos(offset)`
    (the offset is relative to the SMB2 header start — note `readMessage` receives the
    buffer already positioned past the header, so absolute positioning must account for
    `header.getHeaderStartPosition()`; compare `SMB2NegotiateResponse.readNegotiateContextList`
    which does `buffer.rpos(negotiateContextOffset)` at lines 67–96). Then loop over the
    chained contexts (`Next` offsets) and decode the `RqLs` (lease) response context into
    a new field with a getter. Add fields + getters mirroring the existing `fileId`
    accessor (lines 90–92).
  - **Model to copy — Negotiate response context parsing.**
    `SMB2NegotiateResponse` (messages/SMB2NegotiateResponse.java lines 52–96) reads
    offset+count, repositions with `buffer.rpos(offset)`, and loops calling
    `SMB2NegotiateContext.factory(buffer)`. The create-context reader is structurally identical.

### 1.3 Supporting enums

- `com/hierynomus/mssmb2/SMB2CreateOptions.java` — full set of create options; includes
  `FILE_DIRECTORY_FILE(0x1)` (line 34). `EnumWithValue`-based.
- `com/hierynomus/mssmb2/SMB2ShareAccess.java`, `SMB2CreateDisposition.java` — exist,
  standard. `SMB2ImpersonationLevel.java` exists.
- **No oplock-level / lease-state enum exists.** Grep for `OplockLevel` / `LeaseState`
  finds only inline comments (SMB2CreateRequest line 65, SMB2CreateResponse lines 48–49)
  and the `SMB2_OPLOCK_BREAK` references. A new enum
  `SMB2OplockLevel` (NONE 0x00, II 0x01, EXCLUSIVE 0x08, BATCH 0x09, LEASE 0xFF) and a
  `LeaseState` bit-set (READ 0x1, HANDLE 0x2, WRITE 0x4) must be added in
  `com/hierynomus/mssmb2/`.

---

## 2. Create-context infrastructure

- **Confirmed: there is NO general create-context abstraction** (neither request nor
  response). The only "create context" tokens in the codebase are the hardcoded
  offset/length zeros (SMB2CreateRequest lines 93–94) and the ignore-comment
  (SMB2CreateResponse lines 61–63). No `SMB2CreateContext*` class exists anywhere
  (`find ... -name "SMB2CreateContext*"` returns nothing).
- **Where the new model should live:** package `com.hierynomus.mssmb2.messages` (alongside
  the create request/response) or a new sub-package
  `com.hierynomus.mssmb2.messages.create` mirroring the existing
  `com.hierynomus.mssmb2.messages.negotiate` package (dir:
  `messages/negotiate/` containing `SMB2NegotiateContext.java` + concrete contexts +
  `SMB2NegotiateContextType.java`). Recommended new files:
  - `SMB2CreateContextRequest` (abstract base; `write(SMBBuffer)` computing the 16-byte
    context header: Next(4), NameOffset(2), NameLength(2), Reserved(2), DataOffset(2),
    DataLength(4), then the 4-byte name e.g. `"RqLs"`, then the data). Mirror
    `messages/negotiate/SMB2NegotiateContext.java` `write()`/`writeContextHeader()`
    (lines 46–65) and its `factory()` dispatch (lines 67–81).
  - `SMB2CreateContextResponse` (abstract base; `read`).
  - `SMB2LeaseCreateContextRequest` / `...Response` implementing the `RqLs` token with the
    V2 lease layout (LeaseKey 16, LeaseState 4, LeaseFlags 4, LeaseDuration 8, ParentLeaseKey 16,
    Epoch 2, Reserved 2) — V2 is required for *directory* leasing (SMB 3.x).
  - Optionally `SMB2CreateContextType` enum keyed by the 4-byte ASCII names
    (`RqLs`, `DHnQ`, `MxAc`, etc.) mirroring `SMB2NegotiateContextType.java`.

---

## 3. Directory open + listing path

- **Open:** `DiskShare.openDirectory(...)` (share/DiskShare.java line 144) forces
  `FILE_DIRECTORY_FILE` into create options (line 146) and delegates to `open(...)`,
  which routes through `Share.createFile` (share/Share.java lines 151–158). `createFile`
  builds `SMB2CreateRequest` (line 154) and `sendReceive`s it (line 156). This is the
  single choke point where a directory-lease create context would be attached, and where
  the granted lease (from the response, §1.2) would be recorded.
- **Listing:** `Directory.list()` / `iterator()` (share/Directory.java lines 46–113).
  The inner `DirectoryIterator` (lines 138–214) issues `SMB2_QUERY_DIRECTORY` via
  `share.queryDirectory(...)` (line 192 → Share.java line 200, building
  `SMB2QueryDirectoryRequest` / parsing `SMB2QueryDirectoryResponse`). The first call uses
  `SMB2_RESTART_SCANS` (lines 184–185); subsequent calls page until
  `STATUS_NO_MORE_FILES` / `STATUS_NO_SUCH_FILE` (lines 201–207).
- **Caching: confirmed NONE.** Every `list()` constructs a fresh `DirectoryIterator`
  (line 112) and re-issues QUERY_DIRECTORY from scratch (`queryDirectory(true)` in the
  ctor, line 148). There is no member cache, no per-`Directory` retained result, and no
  invalidation hook. The only state retained across the paging loop is `currentBuffer`
  (line 141), used purely to detect the macOS "repeated identical response" bug (lines
  199–207) — not a cache. Directory-lease caching (cache listing while holding a
  read/handle lease, invalidate on lease break) would be **net-new** and would live on
  `Directory` (and/or a share-level open table keyed by lease key).

---

## 4. Inbound / async packet handling (lease breaks)

### 4.1 Receive chain

- `Connection` (connection/Connection.java) is the `PacketReceiver`. Its `handle(...)`
  (line 285) delegates to `packetHandlerChain`. The chain is built in `init()`
  (**lines 121–128**), in order:
  1. `SMB3DecryptingPacketHandler`
  2. `SMB2CompoundedPacketHandler`
  3. `SMB2IsOutstandingPacketHandler`
  4. `SMB2SignatureVerificationPacketHandler`
  5. `SMB2CreditGrantingPacketHandler`
  6. `SMB2AsyncResponsePacketHandler`
  7. `SMB2ProcessResponsePacketHandler`
  8. `SMB1PacketHandler` → `DeadLetterPacketHandler`
- Inbound bytes are decoded by `SMB2PacketFactory.read` (SMB2PacketFactory.java line 24)
  into `SMB2PacketData`, dispatched via the `DelegatingSMBMessageConverter` (Connection.java
  lines 325–351).

### 4.2 Server-initiated packet detection — partially present, non-functional

- `SMB2PacketData.isOplockBreakNotification()` (SMB2PacketData.java **lines 65–67**)
  already returns true when `messageId == 0xFFFFFFFFFFFFFFFF` **and**
  `command == SMB2_OPLOCK_BREAK`. (SMB2/3 lease breaks use the same command 0x12.)
- `SMB2IsOutstandingPacketHandler.doSMB2Handle` (packet/SMB2IsOutstandingPacketHandler.java
  **lines 47–56**) special-cases it: `if (!outstandingRequests.isOutstanding(messageId)
  && !packetData.isOplockBreakNotification())` → dead-letter; **else** `next.handle(...)`.
  So a break notification is *passed down the chain* rather than dead-lettered.
- **The break then dies downstream**, because nothing handles it:
  - `SMB2CreditGrantingPacketHandler` (line 41) just grants credits and forwards — OK.
  - `SMB2AsyncResponsePacketHandler.doSMB2Handle` (packet/SMB2AsyncResponsePacketHandler.java
    **lines 46–48**) calls `outstandingRequests.getRequestByMessageId(0xFFFF...)` → returns
    null → **NPE at line 48** (`request.getTimestamp()`). This is the first hard failure.
  - Even if that were guarded, `SMB2ProcessResponsePacketHandler.doSMB2Handle`
    (packet/SMB2ProcessResponsePacketHandler.java **lines 54–66**) again does
    `getRequestByMessageId(...)` (line 55, null for a break) and calls
    `smb2Converter.readPacket(...)`. `SMB2MessageConverter.getPacketInstance`
    (SMB2MessageConverter.java **lines 73–76**) has `case SMB2_OPLOCK_BREAK:` falling into
    `default:` which **logs an error and throws `SMBRuntimeException`** ("Unknown SMB2
    Message Command type"). So there is currently **no model class** for an oplock/lease
    break response at all.
- **`SMB2MessageCommandCode.SMB2_OPLOCK_BREAK(0x12)` IS present** (SMB2MessageCommandCode.java
  **line 41**).

### 4.3 Exact classes/methods to add for lease-break routing + ack

1. **New break-notification handler** inserted into the chain in `Connection.init()`
   (Connection.java lines 121–128), positioned **after** `SMB2IsOutstandingPacketHandler`
   (line 123) and **before** `SMB2AsyncResponsePacketHandler` (line 126) — it must
   intercept break notifications so they never reach the request-correlation handlers
   (which NPE/throw on the synthetic messageId). It should `canHandle` ==
   `packetData.isOplockBreakNotification()` and otherwise forward.
2. **New parse model(s):** `SMB2OplockBreakNotification` and
   `SMB2LeaseBreakNotification` (command 0x12, two distinct body layouts distinguished by
   StructureSize: 24 = oplock break, 44 = lease break). These need to be wired into
   `SMB2MessageConverter.getPacketInstance` (SMB2MessageConverter.java line 73, currently
   the throwing branch). Note these are server→client; the converter is normally called
   with a matching request — for breaks there is no request, so the new dedicated handler
   in step 1 should parse directly rather than going through `readPacket`.
3. **Lease-break acknowledgement (send path):** the client replies with
   `SMB2_LEASE_BREAK_ACK` (also command 0x12, StructureSize 36) on its own messageId.
   A new request model `SMB2LeaseBreakAcknowledgment` is needed, sent through the normal
   `Session.send` / `Connection.send` (Connection.java line 216). The handler from step 1
   must locate the affected open (by LeaseKey), flush/invalidate cached state (directory
   listing cache from §3), downgrade the recorded lease state, and send the ack with the
   new (downgraded) lease state.
4. **Dispatch to application/cache:** there is an event bus (`SMBEventBus`,
   used in Connection.java lines 56–57, 111, 191) that could publish a lease-break event,
   but currently no lease/oplock events exist — a new event type would be the clean
   integration point for cache invalidation.

---

## 5. Negotiate / capabilities / dialects

- **Dialects:** `com/hierynomus/mssmb2/SMB2Dialect.java` — `SMB_2_0_2, SMB_2_1, SMB_2XX,
  SMB_3_0, SMB_3_0_2, SMB_3_1_1` (lines 21–27). `isSmb3x()` (line 39) and
  `supportsSmb3x(Set)` (line 49) exist for gating SMB3-only directory-lease code.
- **Capabilities enum:** `com/hierynomus/mssmb2/SMB2GlobalCapability.java` already defines
  `SMB2_GLOBAL_CAP_LEASING(0x02)` (line 26) and `SMB2_GLOBAL_CAP_DIRECTORY_LEASING(0x20)`
  (line 29).
- **But leasing caps are NOT advertised.** `SmbConfig.getClientCapabilities()`
  (SmbConfig.java **lines 282–294**) builds the client capability set and adds only
  `LARGE_MTU` (line 286), and conditionally `DFS` / `ENCRYPTION`. It never adds
  `SMB2_GLOBAL_CAP_LEASING` or `SMB2_GLOBAL_CAP_DIRECTORY_LEASING`. These must be added
  here (gated on SMB3 + a config toggle). They flow into the request via
  `SMB2NegotiateRequest.putCapabilities` (SMB2NegotiateRequest.java lines 132–139).
- **Negotiated dialect storage:** `ConnectionContext` (connection/ConnectionContext.java)
  stores the negotiated dialect inside `NegotiatedProtocol` (set in `negotiated(...)`
  line 81). Crucially, **lease-gating helpers already exist**:
  - `supportsFileLeasing()` — ConnectionContext.java **lines 181–183** (checks server
    cap `SMB2_GLOBAL_CAP_LEASING`).
  - `supportsDirectoryLeasing()` — ConnectionContext.java **lines 199–201** (checks
    `negotiatedProtocol.getDialect().isSmb3x()` **and** server cap
    `SMB2_GLOBAL_CAP_DIRECTORY_LEASING`).
  Lease code should gate on these. Reachable via `Connection.getConnectionContext()`
  (Connection.java line 314).

---

## 6. Build / test layout

- **Build:** `smbj/build.gradle`. Gradle with `jvm-test-suite`, `groovy`, `jacoco`.
  Java release target **8** (`options.release = 8`, build.gradle line ~52).
  `configurations.implementation.transitive = false`.
- **Unit tests (`test` suite):** Spock + Groovy (and some JUnit-Jupiter + Mockito +
  AssertJ). Configured in the `testing { suites { ... } }` block (build.gradle ~lines
  88–119). Uses `useJUnitJupiter()`, plus `SPOCK_CORE`, `mockito-core:5.4.0`,
  `assertj-core:3.24.2`, CGLIB/Objenesis, `commons-io`, Logback. Includes patterns
  `**/*Test.*` and `**/*Spec.*`.
  - Sources: `src/test/groovy/...` (Spock `*Spec.groovy`, the majority — e.g.
    `src/test/groovy/com/hierynomus/mssmb2/messages/SMB2CreateResponseSpec.groovy`) and
    `src/test/java/...` (JUnit). New message (de)serialization tests belong as Spock specs
    in `src/test/groovy/com/hierynomus/mssmb2/messages/`. Spock pattern: extend
    `AbstractPacketReadSpec`, parse hex via `ByteArrayUtils.parseHex`, `convert(bytes)`
    (see SMB2CreateResponseSpec.groovy lines 25–54).
- **Integration tests (`integrationTest` suite):** defined in build.gradle ~lines 124–155.
  - Deps: **Testcontainers 1.19.0** (`testcontainers` + `junit-jupiter`),
    commons-compress, logback. JUnit Jupiter (`@ParameterizedTest`, `@Testcontainers`).
  - Sources: `src/it/java` (and `src/it/groovy` if present), resources `src/it/resources`,
    docker image context `src/it/docker-image`.
  - **Real SMB server:** `src/it/java/com/hierynomus/smbj/testcontainers/SambaContainer.java`
    builds an Alpine + **Samba** container from `src/it/docker-image` (Dockerfile built in
    code, lines 56–86), exposing port **445** (fixed-mapped, lines 95–96). Samba config:
    `src/it/docker-image/smb.conf` — shares `public`, `readonly`, `user`, `dfs`. **Note:**
    smb.conf has **no `oplocks` / `kernel oplocks` / `level2 oplocks` directives**, so
    leasing behavior at the server is default Samba — an integration test exercising
    *directory lease breaks* may need an added share with explicit oplock/lease settings.
  - Existing ITs (`src/it/java/com/hierynomus/smbj/`):
    `IntegrationTest`, `SMB2DirectoryIntegrationTest`, `SMB2FileIntegrationTest`,
    `ChangeNotifyIntegrationTest`, `DfsIntegrationTest`, `AnonymousIntegrationTest`.
    `IntegrationTest.java` (lines 38–112) shows the harness: `@Container static
    SambaContainer`, `samba.withAuthenticatedClient(config, ctx, session -> { ... })`,
    parameterized over `TestingUtils#defaultTestingConfig`. A directory-lease IT (two
    sessions / opens, trigger a break by modifying the directory from a second handle)
    would extend this pattern.
- **Running a single test:**
  - Unit: `./gradlew test --tests "com.hierynomus.mssmb2.messages.SMB2CreateResponseSpec"`
  - Integration: `./gradlew integrationTest --tests "com.hierynomus.smbj.IntegrationTest"`
    (the `integrationTest` task `shouldRunAfter(test)` and is wired into `release` /
    not into `build`; it requires Docker for Testcontainers).
  - Full build (README §"Building"): `./gradlew clean build`.

---

## Change-points checklist (foundational → advanced)

1. **[enums] Add oplock-level + lease-state types.** New `SMB2OplockLevel`
   (incl. `LEASE=0xFF`) and `LeaseState` / `LeaseFlags` in `com/hierynomus/mssmb2/`.
   None exist today (only inline comments at SMB2CreateRequest:65, SMB2CreateResponse:48–49).

2. **[create-context model] Build the missing abstraction.** New
   `SMB2CreateContextRequest` / `SMB2CreateContextResponse` base + `RqLs` lease V1/V2
   contexts, in a new `com/hierynomus/mssmb2/messages/create/` package (mirror
   `messages/negotiate/SMB2NegotiateContext.java`:46–81). Currently absent entirely.

3. **[request serialization] Serialize create contexts + oplock level.**
   `messages/SMB2CreateRequest.java`: set RequestedOplockLevel (line 65) and replace the
   hardcoded `CreateContextsOffset/Length = 0` (lines 93–94) with real 8-byte-aligned,
   `Next`-chained context serialization after the name (after line 96). Add a constructor
   param for oplock level + contexts (ctor lines 44–59). Template: `SMB2NegotiateRequest`
   lines 77–130.

4. **[response parsing] Parse the granted lease.**
   `messages/SMB2CreateResponse.java`: capture OplockLevel (line 48) and parse the
   create contexts instead of ignoring them (lines 61–63); add lease field + getter.
   Template: `SMB2NegotiateResponse.readNegotiateContextList` lines 67–96.

5. **[negotiate caps] Advertise leasing.** `SmbConfig.getClientCapabilities()`
   (SmbConfig.java lines 282–294): add `SMB2_GLOBAL_CAP_LEASING` and
   `SMB2_GLOBAL_CAP_DIRECTORY_LEASING` (gated on SMB3 + a config flag). Gate runtime use
   on existing `ConnectionContext.supportsDirectoryLeasing()` (ConnectionContext.java
   199–201).

6. **[open wiring] Request a directory lease on open.** `DiskShare.openDirectory`
   (DiskShare.java 144) → `Share.createFile` (Share.java 151–158): attach a `RqLs` V2
   context when directory leasing is negotiated; record the granted lease + lease key
   against the `Directory` / an open table.

7. **[break detection routing] Add a break handler to the chain.** Insert a new handler in
   `Connection.init()` (Connection.java 121–128) between `SMB2IsOutstandingPacketHandler`
   (123) and `SMB2AsyncResponsePacketHandler` (126). Detection already exists
   (`SMB2PacketData.isOplockBreakNotification()` 65–67; pass-through at
   `SMB2IsOutstandingPacketHandler` 47–56). This prevents the current NPE at
   `SMB2AsyncResponsePacketHandler`:48 and the throw at `SMB2MessageConverter`:73–76.

8. **[break model + ack send] Parse the break, send Lease Break Ack.** New
   `SMB2LeaseBreakNotification` (StructureSize 44) / `SMB2OplockBreakNotification` (24)
   parse models; wire into `SMB2MessageConverter.getPacketInstance` (line 73) or parse
   directly in the new handler. New `SMB2LeaseBreakAcknowledgment` (StructureSize 36)
   request, sent via `Connection.send` (216). Locate affected open by LeaseKey, downgrade
   recorded lease state, send ack.

9. **[caching + invalidation] (advanced) Directory listing cache.** Add an opt-in cache
   on `Directory` (`DirectoryIterator`, Directory.java 138–214 — currently re-queries
   every `list()` with zero caching) populated while a read/handle directory lease is held,
   invalidated by the break handler (step 7/8), ideally via a new `SMBEventBus` lease event
   (bus referenced in Connection.java 56–57, 111, 191).

10. **[tests] (advanced)** Unit Spock specs in `src/test/groovy/.../mssmb2/messages/` for
    context (de)serialization (template SMB2CreateResponseSpec.groovy); integration test
    in `src/it/java/com/hierynomus/smbj/` using `SambaContainer` (possibly a new share in
    `src/it/docker-image/smb.conf` with explicit oplock/lease config) to exercise a real
    directory-lease grant + break + ack.
