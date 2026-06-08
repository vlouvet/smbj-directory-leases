# 04 — Advertising Leasing Capabilities + Gating Lease Use on the Negotiated Dialect/Caps

> Milestone 4 of `00-overview.md`. No hard code dependency on specs 01-03 (this
> only touches NEGOTIATE plumbing + a config flag), but it **pairs with spec 05**:
> spec 05's `DiskShare.openDirectory` lease path is the consumer of the runtime
> gate (`ConnectionContext.supportsDirectoryLeasing()`) this spec documents and
> exercises. TDD: write the failing cases in §6 first, implement to green, keep all
> existing tests passing.

All paths below are relative to `smbj/` unless noted.

---

## 0. STATUS — IMPLEMENTED & VERIFIED LIVE (2026-06-07)

This milestone is **done**. Implementation landed in `SmbConfig.java`:
- new field `directoryLeasingEnabled` (default **true**), copy-ctor + default-config wiring,
  getter `isDirectoryLeasingEnabled()`, builder `withDirectoryLeasingEnabled(boolean)`;
- `getClientCapabilities()` now adds `SMB2_GLOBAL_CAP_LEASING (0x02)` **and**
  `SMB2_GLOBAL_CAP_DIRECTORY_LEASING (0x20)` on SMB3 when enabled.

**Empirical finding (corrects §1 below):** advertising the client capability is **not**
"mostly informational" — it is a **hard precondition**. With stock smbj the live smoke
test (`LiveSambaSmokeIntegrationTest` vs Samba 4.23.8 on `.12`) asserted
`supportsDirectoryLeasing()` and got **false**: Samba (like Windows) only echoes the
leasing caps in its NEGOTIATE **response**, and only grants leases, **when the client
advertised them in the request first**. After adding the two caps, the same test went
**green** (`supportsDirectoryLeasing() == true`) with the 273-test unit baseline still green.
So: client-side advertisement gates the server-side advertisement that the runtime gate
(`ConnectionContext.supportsDirectoryLeasing()`) reads. Treat (b)/(c) below through that lens.

---

## 1. Purpose & scope

For a directory lease to work end-to-end three things must line up:

1. The connection negotiates an **SMB 3.x** dialect (3.0 / 3.0.2 / 3.1.1).
2. The **server** advertises `SMB2_GLOBAL_CAP_DIRECTORY_LEASING (0x20)` in its
   NEGOTIATE response capabilities.
3. The **client** only *requests* a lease (sends `RequestedOplockLevel = LEASE`
   + a `RqLs` V2 context) when (1) and (2) hold.

smbj today gets (1) for free (it negotiates up to 3.1.1, see §3) and already has
the runtime gate for (2)+(3) in place — `ConnectionContext.supportsDirectoryLeasing()`
(`connection/ConnectionContext.java:199`) correctly returns
`negotiatedProtocol.getDialect().isSmb3x() && supports(DIRECTORY_LEASING)`. What is
missing is that **the client never advertises LEASING/DIRECTORY_LEASING in its own
NEGOTIATE request** — `SmbConfig.getClientCapabilities()` (`SmbConfig.java:282-294`)
only ever sets `LARGE_MTU` (+ `DFS`/`ENCRYPTION` when toggled).

This spec:

- **(a)** Adds `SMB2_GLOBAL_CAP_LEASING (0x02)` and
  `SMB2_GLOBAL_CAP_DIRECTORY_LEASING (0x20)` to the advertised client capabilities
  in `SmbConfig.getClientCapabilities()`, behind a new `SmbConfig` builder toggle
  (`withDirectoryLeasing(boolean)`, default **ON**) — mirroring how `isDfsEnabled()`
  / `isEncryptData()` gate `DFS` / `ENCRYPTION` today.
- **(b)** Documents that the server must *also* advertise the cap and that
  `ConnectionContext.supportsDirectoryLeasing()` is the **single runtime gate** every
  lease open (spec 05) must check before requesting a lease. Confirms the two getters
  are already correct and need no change.
- **(c)** Notes the dialect interaction: both the advertised cap and the runtime
  gate are inert unless an SMB 3.x dialect is negotiated.

### The load-bearing distinction (client vs server direction)

The client advertising `DIRECTORY_LEASING` in its NEGOTIATE *request* is **mostly
informational** for the client→server direction — per [MS-SMB2] the server decides
whether to grant directory leases based on its own capability and the dialect, and
Samba grants directory leases to a 3.x client regardless of whether the client set
the bit in its request. So part (a) is "be a well-behaved, spec-faithful client";
it is **not** what makes leasing work.

**The operative requirement is part (b):** the client must only *request* leases
when `ConnectionContext.supportsDirectoryLeasing()` is `true` — i.e. when the
**server** advertised `0x20` in its NEGOTIATE *response* and the negotiated dialect
is 3.x. That gate is enforced at the lease-open site in spec 05, not here. This spec
makes the gate explicit and proves it both offline (mocked negotiate response) and
live (server at .12 actually advertises `0x20`).

**Out of scope (later specs):** actually attaching the lease context / consulting
the gate in `DiskShare.openDirectory` (spec 05); break handling (spec 06).

---

## 2. Dependencies

- **No hard dependency** on specs 01-03 — this spec compiles and tests independently
  (it only touches `SmbConfig`, a NEGOTIATE-request capability set, and a
  `ConnectionContext` getter, all of which already exist).
- **Pairs with spec 05.** Spec 05's `DiskShare.openDirectory` lease path is the sole
  consumer of `supportsDirectoryLeasing()`; this spec defines/asserts the gate, spec
  05 enforces it ("only request a lease iff the gate is true").

Pre-existing types this spec relies on (all present, confirmed):

- `com.hierynomus.mssmb2.SMB2GlobalCapability` — enum incl.
  `SMB2_GLOBAL_CAP_LEASING(0x02L)` (`:25`) and
  `SMB2_GLOBAL_CAP_DIRECTORY_LEASING(0x20L)` (`:29`).
- `com.hierynomus.mssmb2.SMB2Dialect` — `isSmb3x()` (`:39-41`),
  `supportsSmb3x(Set)` (`:49-56`); smbj negotiates up to `SMB_3_1_1(0x0311)`
  (default dialect set, `SmbConfig.java:114`).

---

## 3. Background — capability bits, client vs server direction, dialect gating

### 3.1 The bits ([MS-SMB2] 2.2.4 NEGOTIATE Response `Capabilities`)

| Name | Value | Meaning |
|------|-------|---------|
| `SMB2_GLOBAL_CAP_LEASING`           | `0x02` | File leasing. Not valid for 2.0.2. |
| `SMB2_GLOBAL_CAP_DIRECTORY_LEASING` | `0x20` | Directory leasing. **SMB 3.0+ only** (invalid for 2.0.2 / 2.1). |

(See `docs/ms-smb2-lease-spec.md` §7.) Directory leasing rides on the V2 lease
create context, which only exists in the 3.x dialect family — hence the dialect
gate is intrinsic, not just a smbj convention.

### 3.2 Client direction (NEGOTIATE request) — what smbj writes

`SmbConfig.getClientCapabilities()` (`SmbConfig.java:282-294`) returns the
`Set<SMB2GlobalCapability>` that feeds the NEGOTIATE request. The flow:

```
SmbConfig.getClientCapabilities()
  → ConnectionContext ctor copies it into clientCapabilities   (ConnectionContext.java:72)
  → ... negotiate request is built with these capabilities ...
  → SMB2NegotiateRequest.putCapabilities() writes them          (SMB2NegotiateRequest.java:132-139)
        — but ONLY when supportsSmb3x(dialects) is true; otherwise the
          Capabilities field is written as 4 reserved zero bytes.
```

So even after part (a), the bits are only emitted on the wire for an SMB 3.x
negotiate — exactly the dialect gate we want. Note `getClientCapabilities()` itself
already short-circuits to an empty set when `!supportsSmb3x(dialects)`
(`SmbConfig.java:283-285`), so the new LEASING bits are never added for a pure
2.x-only config.

**This direction is informational** (see §1). It does not gate whether the server
grants a lease.

### 3.3 Server direction (NEGOTIATE response) — the operative gate

The server's advertised capabilities land in the `Server` object and are surfaced
through `ConnectionContext.supports(...)` (`ConnectionContext.java:125-127`,
`getServerCapabilities()` `:105-107`). The runtime gate:

```java
// ConnectionContext.java:199-201  (ALREADY CORRECT — do not modify)
public boolean supportsDirectoryLeasing() {
    return negotiatedProtocol.getDialect().isSmb3x()
        && supports(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DIRECTORY_LEASING);
}
```

This ANDs the dialect gate (3.x) with the **server's** advertised `0x20`. It is the
single source of truth spec 05 must consult. Its sibling
`supportsFileLeasing()` (`:181-183`) checks the server's `LEASING` bit (no explicit
dialect AND, because file leasing is also a 2.1 feature; directory leasing adds the
`isSmb3x()` guard).

### 3.4 Dialect gating summary

- smbj's default dialect set already includes 3.1.1/3.0.2/3.0 (`SmbConfig.java:114`),
  so SMB 3.x is negotiated against any 3.x-capable server.
- If a caller restricts dialects to 2.x only, `getClientCapabilities()` returns the
  empty set (no leasing bits sent) **and** `supportsDirectoryLeasing()` returns
  `false` (because `isSmb3x()` is false) — both directions degrade safely.

---

## 4. Files to change

### 4.1 `src/main/java/com/hierynomus/smbj/SmbConfig.java` — advertise the caps + new toggle

**(a) New field** (alongside the other boolean toggles, after `encryptData` at `:93`):

```java
private boolean directoryLeasing;
```

**(b) New getter** (alongside `isEncryptData()` at `:265-267`):

```java
/**
 * Whether the client should advertise (and use) SMB3 file/directory leasing.
 * When enabled, the NEGOTIATE request advertises SMB2_GLOBAL_CAP_LEASING and
 * SMB2_GLOBAL_CAP_DIRECTORY_LEASING (only on an SMB 3.x negotiate). Whether a lease
 * is actually requested is additionally gated at open time on the server having
 * advertised the capability — see ConnectionContext.supportsDirectoryLeasing().
 */
public boolean isDirectoryLeasing() {
    return directoryLeasing;
}
```

**(c) Wire the bits into `getClientCapabilities()`** (`:282-294`). Add after the
`isEncryptData()` block (`:290-292`), inside the existing `supportsSmb3x` guard:

```java
public Set<SMB2GlobalCapability> getClientCapabilities() {
    if (!SMB2Dialect.supportsSmb3x(dialects)) {
        return EnumSet.noneOf(SMB2GlobalCapability.class);
    }
    EnumSet<SMB2GlobalCapability> set = EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU);
    if (isDfsEnabled()) {
        set.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DFS);
    }
    if (isEncryptData()) {
        set.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION);
    }
    if (isDirectoryLeasing()) {                                              // NEW
        set.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LEASING);              // 0x02
        set.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DIRECTORY_LEASING);    // 0x20
    }
    return set;
}
```

(`LEASING` is added too: a spec-faithful client that wants directory leasing also
advertises file leasing — and the V2 context lineage assumes both. Keeping them on
one toggle matches the user's mental model "directory leasing on/off". If a finer
split is ever wanted, add a separate `withLeasing(boolean)` later; one toggle is
sufficient for this milestone.)

**(d) Builder default = ON** (in `builder()` at `:103-119`). Add to the fluent chain,
e.g. after `.withEncryptData(false)` (`:119`):

```java
.withDirectoryLeasing(true);
```

(Watch the trailing `;` — it currently terminates the chain on `.withEncryptData(false)`.
Move the `;` to the new last call.)

**(e) Copy-constructor wiring** (`SmbConfig(SmbConfig other)` at `:154-177`). Add
alongside `encryptData = other.encryptData;` (`:175`):

```java
directoryLeasing = other.directoryLeasing;
```

**(f) New builder method** (alongside `withEncryptData` at `:510-513`):

```java
public Builder withDirectoryLeasing(boolean directoryLeasing) {
    config.directoryLeasing = directoryLeasing;
    return this;
}
```

> No `build()` validation is needed: when no 3.x dialect is configured,
> `getClientCapabilities()` already returns the empty set, so an SMB-2-only config
> with `directoryLeasing = true` simply emits no leasing bits (and
> `supportsDirectoryLeasing()` stays false). The toggle is therefore harmless in
> any dialect combination — no analogue of the encryption `build()` guard
> (`:483-485`) is required.

### 4.2 `src/main/java/com/hierynomus/smbj/connection/ConnectionContext.java` — confirm, do not change

- `supportsDirectoryLeasing()` (`:199-201`) — **already correct**:
  `negotiatedProtocol.getDialect().isSmb3x() && supports(DIRECTORY_LEASING)`. This is
  the runtime gate spec 05 consumes. No change.
- `supportsFileLeasing()` (`:181-183`) — `supports(LEASING)`. No change.
- `negotiated(...)` (`:77-87`) sets `negotiatedProtocol` and stores the server in
  `this.server`; the server's advertised caps reach `supports(...)` via
  `server.getCapabilities()` (`:106`, `:126`). Confirmed the negotiate-response path
  populates the server caps before any share open — no change.

### 4.3 No NEGOTIATE-request source change

`SMB2NegotiateRequest.putCapabilities()` (`:132-139`) already serializes whatever
`SmbConfig.getClientCapabilities()` produced (only on a 3.x negotiate). Once §4.1
adds the bits to that set, they flow to the wire with **no change to the request
class**. (No anchor edited here; cited only to confirm the path.)

---

## 5. Method sketches (signatures + logic)

```java
// SmbConfig
public boolean isDirectoryLeasing();                          // new getter, default true
public Set<SMB2GlobalCapability> getClientCapabilities();     // + LEASING,DIRECTORY_LEASING when on & 3.x

// SmbConfig.Builder
public Builder withDirectoryLeasing(boolean directoryLeasing); // default wired true in builder()
```

`getClientCapabilities()` logic (additions only):

```
if !supportsSmb3x(dialects): return {}            // unchanged early-out
set = { LARGE_MTU }
if dfsEnabled:    set += DFS
if encryptData:   set += ENCRYPTION
if directoryLeasing: set += LEASING; set += DIRECTORY_LEASING   // NEW
return set
```

`ConnectionContext.supportsDirectoryLeasing()` — unchanged; reproduced as the gate
spec 05 calls:

```
return negotiatedProtocol.getDialect().isSmb3x()
    && server.getCapabilities().contains(DIRECTORY_LEASING)
```

---

## 6. TDD tests (failing-first where applicable)

### 6.1 `src/test/java/com/hierynomus/smbj/SmbConfigTest.java` (extend) — advertised caps

The existing JUnit-Jupiter `SmbConfigTest` (`:25-42`) is the home for the
config-level assertions. Write these first (they fail until §4.1 lands).

**Test A — default config (3.x dialects) advertises LEASING + DIRECTORY_LEASING.**

```java
@Test
public void defaultConfigAdvertisesLeasingCapabilities() {
    Set<SMB2GlobalCapability> caps = SmbConfig.createDefaultConfig().getClientCapabilities();
    assertThat(caps).contains(
        SMB2GlobalCapability.SMB2_GLOBAL_CAP_LEASING,
        SMB2GlobalCapability.SMB2_GLOBAL_CAP_DIRECTORY_LEASING);
}
```

**Test B — `withDirectoryLeasing(false)` excludes both bits (but keeps LARGE_MTU).**

```java
@Test
public void disabledDirectoryLeasingExcludesLeasingCapabilities() {
    Set<SMB2GlobalCapability> caps = SmbConfig.builder()
        .withDirectoryLeasing(false)
        .build()
        .getClientCapabilities();
    assertThat(caps).doesNotContain(
        SMB2GlobalCapability.SMB2_GLOBAL_CAP_LEASING,
        SMB2GlobalCapability.SMB2_GLOBAL_CAP_DIRECTORY_LEASING);
    assertThat(caps).contains(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU); // sanity
}
```

**Test C — SMB-2-only config never advertises leasing even with the toggle on.**

```java
@Test
public void smb2OnlyConfigAdvertisesNoCapabilities() {
    Set<SMB2GlobalCapability> caps = SmbConfig.builder()
        .withDialects(SMB2Dialect.SMB_2_1, SMB2Dialect.SMB_2_0_2)
        .withDirectoryLeasing(true)
        .build()
        .getClientCapabilities();
    assertThat(caps).isEmpty(); // getClientCapabilities() short-circuits for non-3.x
}
```

(Use AssertJ `org.assertj.core.api.Assertions.assertThat` — already on the test
classpath, cf. `LiveSambaSmokeIT.java:18` — plus imports for `Set`,
`SMB2GlobalCapability`, `SMB2Dialect`. The existing `assertThrows`/`assertDoesNotThrow`
cases stay unchanged.)

### 6.2 `ConnectionContext`-level test (new) — the runtime gate

Add a focused test that proves `supportsDirectoryLeasing()` keys off the **server's**
advertised `0x20` AND the negotiated dialect. `ConnectionContext.negotiated(...)`
and its ctor are package-private (`connection/ConnectionContext.java:67,77`), so put
the test in package `com.hierynomus.smbj.connection`. Mock the negotiate response /
server-capability path with Mockito or Spock (Spock preferred — mirrors the existing
groovy specs under `src/test/groovy/...`).

New file: `src/test/groovy/com/hierynomus/smbj/connection/ConnectionContextSpec.groovy`.

**Test D — server advertises 0x20 on a 3.x dialect → gate true.**
**Test E — server omits 0x20 → gate false.**
**Test F — server advertises 0x20 but dialect is 2.1 → gate false (dialect gate).**

Sketch (Spock; stub the two collaborators the gate reads —
`negotiatedProtocol.getDialect()` and `server.getCapabilities()`):

```groovy
def "supportsDirectoryLeasing is true only when server advertises 0x20 AND dialect is 3.x"() {
    given:
      def server = Mock(Server) { getCapabilities() >> serverCaps }
      def negotiated = new NegotiatedProtocol(dialect, 0, 0, 0, false)
      def ctx = // construct ConnectionContext, inject server + negotiatedProtocol
                // (via the package-private ctor + a test-visible setter, or a small
                //  helper that sets the two private fields the gate reads)
    expect:
      ctx.supportsDirectoryLeasing() == expected
    where:
      dialect                 | serverCaps                                          || expected
      SMB2Dialect.SMB_3_1_1   | EnumSet.of(SMB2_GLOBAL_CAP_DIRECTORY_LEASING)       || true
      SMB2Dialect.SMB_3_1_1   | EnumSet.noneOf(SMB2GlobalCapability)                || false
      SMB2Dialect.SMB_2_1     | EnumSet.of(SMB2_GLOBAL_CAP_DIRECTORY_LEASING)       || false
}
```

If wiring the private `negotiatedProtocol`/`server` fields proves awkward from the
test, prefer driving `negotiated(NegotiationContext)` with a mocked
`SMB2NegotiateResponse` (returning the dialect) + a mocked `Server` (returning the
caps) — that exercises the real `negotiated(...)` path (`:77-87`) end-to-end and is
the more faithful test. Either way the three rows above are the assertions.

> Note: these gate rows are *characterization* tests of already-correct code
> (`supportsDirectoryLeasing()` is unchanged by this spec). They are not failing-first;
> they lock the gate's contract so spec 05 can rely on it and so a future refactor
> can't silently drop the dialect AND. Mark them as such in a comment.

### 6.3 Live assertion (already present) — server at .12 advertises 0x20

`src/it/java/com/hierynomus/smbj/smoke/LiveSambaSmokeIT.java:67-70` already asserts
the live precondition:

```java
assertThat(conn.getConnectionContext().supportsDirectoryLeasing())
    .as("server at %s:%d must advertise SMB2_GLOBAL_CAP_DIRECTORY_LEASING", HOST, PORT)
    .isTrue();
```

No change required — this IT is the live counterpart to Test D and already passes
against the .12 Samba 4.23.8 server (`smb3 directory leases = Yes`). It transitively
validates that the default config (which now also advertises the client-side bits)
still negotiates 3.x cleanly. Run:

```
SMBJ_IT_HOST=<smb-host> ./gradlew integrationTest --tests "*LiveSambaSmokeIT"
```

---

## 7. Acceptance criteria

1. `SmbConfig` has a new `directoryLeasing` boolean (default **true**), a public
   `isDirectoryLeasing()` getter, and a `Builder.withDirectoryLeasing(boolean)`
   method; the flag is wired in `builder()` (default true) and copied in the
   `SmbConfig(SmbConfig)` copy-constructor.
2. With the toggle on **and** at least one SMB 3.x dialect configured,
   `getClientCapabilities()` includes both `SMB2_GLOBAL_CAP_LEASING (0x02)` and
   `SMB2_GLOBAL_CAP_DIRECTORY_LEASING (0x20)` (in addition to the existing
   `LARGE_MTU` and any `DFS`/`ENCRYPTION`). With the toggle off, neither leasing bit
   is present. (Tests A, B.)
3. An SMB-2-only config returns an empty capability set regardless of the toggle —
   no leasing bits are emitted on a non-3.x negotiate. (Test C.) Consequently the
   NEGOTIATE request (`SMB2NegotiateRequest.putCapabilities`, `:132-139`) emits the
   leasing bits only on a 3.x negotiate, with **no change to the request class**.
4. `ConnectionContext.supportsDirectoryLeasing()` is confirmed unchanged and is the
   single runtime gate: it returns true **iff** the negotiated dialect is 3.x **and**
   the server advertised `0x20`. (Tests D, E, F.) Spec 05 must call this gate before
   requesting any lease; client-side advertising (item 2) is informational and does
   not by itself enable leasing.
5. The live `LiveSambaSmokeIT` assertion (`:67-70`) continues to pass against the
   .12 server (server advertises `0x20`).
6. All existing tests remain green (`./gradlew clean build`), compiling to Java 8
   (`build.gradle options.release = 8`).
