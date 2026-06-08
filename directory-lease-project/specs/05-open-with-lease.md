# 05 — Open a Directory With a Lease + `LeaseManager` + ParentLeaseKey Threading

> Milestone 5 of `00-overview.md`. Depends on specs 02 (`LeaseKey`,
> `SMB2LeaseState`/`Flags`, `SMB2OplockLevel`, `SMB2LeaseCreateContext` request
> writer, `SMB2LeaseResponseContext` parser) and 03 (CREATE request/response carry
> contexts + oplock level; `SMB2CreateResponse.getLeaseResponseContext()`) and 04
> (`ConnectionContext.supportsDirectoryLeasing()` gating, client advertises
> DIRECTORY_LEASING). Feeds 06 (break routing resolves a break → the registered
> `LeaseEntry`) and 07 (`LeasedDirectoryCache` hangs off the granted `LeaseEntry`).
> TDD: write the failing tests in §6 first, implement §4/§5 to green, keep all
> existing tests passing.

All paths below are relative to `smbj/` unless noted. Line anchors are from the
current checkout (read-only inspection performed; no source modified by this spec).

---

## 1. Purpose & scope

After spec 03, `SMB2CreateRequest` *can* carry an `SMB2LeaseCreateContext` and
`SMB2CreateResponse` *can* parse the granted lease — but nothing ever asks for one.
This milestone makes `DiskShare.openDirectory` actually **request a directory
lease** on the open, and stands up the client-side bookkeeping that every later
milestone needs:

- A **`LeaseManager`** (the "lease table") owned per-`Connection`, keyed by
  `LeaseKey` → `LeaseEntry`. This is the registry an async lease break (spec 06)
  resolves against, and the home the directory cache (spec 07) attaches to.
- A **`LeaseEntry`** holding `{leaseKey, parentLeaseKey, requestedState,
  grantedState, epoch, path, fileId}` plus a slot for the cache (spec 07).
- A **per-directory-node `LeaseKey`**: minted once per path and reused for the
  lifetime of that node (Apple's per-node, not per-handle, key — §3.2).
- The modified open flow: build a **V2** `RqLs` context (state
  `READ_CACHING | HANDLE_CACHING`), set `ParentLeaseKey` from the enclosing
  directory's `LeaseEntry` when one exists (+ `PARENT_LEASE_KEY_SET`),
  `RequestedOplockLevel = LEASE (0xFF)`, **register the `LeaseEntry` BEFORE sending
  the CREATE**, then on the response fold in the granted state + epoch (or remove
  the entry if no lease was granted).
- The whole path is **gated on `supportsDirectoryLeasing()`**; when the server did
  not advertise directory leasing, `openDirectory` falls back to today's plain open
  verbatim (no context, oplock NONE, no registry entry).

**Out of scope (later specs):** inbound break parse/route/ack (06); serving and
invalidating cached `list()` (07); file (non-directory) leases; lease
upgrade/downgrade optimization. This milestone proves *"the server grants us an RH
directory lease and we threaded the parent key"* and leaves the granted handle open
and registered for 06/07 to use.

### 1.1 Register-before-send (load-bearing ordering)

The break for a lease can arrive on the wire **before** the CREATE response that
grants it — the server may grant the lease to us and immediately break it (e.g. a
concurrent mutation in the directory), and the async `OPLOCK_BREAK` is a separate,
unsolicited message with `MessageId = 0xFFFF…` that is not ordered against our
CREATE reply. Apple handles exactly this by adding the lease to the global table
**before** issuing the Create (`smbfs_add_update_lease(..., SMBFS_LEASE_ADD, ...)`,
`smbfs_smb_2.c:4376`), and removing it if the Create fails or grants no lease.

We mirror that: `LeaseManager.register(entry)` is called **before**
`Share.createFile(...)` is invoked; the receive path for breaks (spec 06) can then
always resolve the `LeaseKey` to a `LeaseEntry`. If the CREATE fails or comes back
with no lease (`OplockLevel != LEASE` / no `RqLs` response context), we
`LeaseManager.unregister(leaseKey)`. This is the single most important ordering
constraint in this milestone — see Test E (§6) which asserts the entry is present
in the registry at send time.

---

## 2. Dependencies (specs 02, 03, 04 → feeds 06, 07)

Consumed (must be green before implementing §4/§5):

**Spec 02 — `com.hierynomus.mssmb2`:**
- `LeaseKey` — 16-byte value object (UUID-derived), `equals`/`hashCode` so it keys a
  `Map<LeaseKey, LeaseEntry>`. Assume a `LeaseKey.generate()` / `new LeaseKey()`
  mint of 16 random bytes, and `byte[] getBytes()` / a 16-byte accessor.
- `SMB2LeaseState` — bitmask `EnumWithValue` with `READ_CACHING`, `HANDLE_CACHING`;
  set-membership helpers (`isReadHandle`, etc.).
- `SMB2LeaseFlags.SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET (0x04)`.
- `SMB2OplockLevel.LEASE (0xFF)`.
- `com.hierynomus.mssmb2.messages.create.SMB2LeaseCreateContext` — request writer.
  Assume a constructor/builder taking `(LeaseKey leaseKey, Set<SMB2LeaseState>
  state, LeaseKey parentLeaseKey /* nullable */, int epoch)` that emits V2 (52B)
  when `parentLeaseKey != null` OR always-V2-for-dirs, and `.asCreateContext()`
  producing an `SMB2CreateContext` (`name = "RqLs"`). (Directory leases are always
  V2 — §3.1.) If spec 02 names the parent param differently, adapt; the operative
  inputs are leaseKey, state, parentLeaseKey, epoch=0.
- `com.hierynomus.mssmb2.messages.create.SMB2LeaseResponseContext` — exposes
  `getLeaseKey()`, `getLeaseState()` (`Set<SMB2LeaseState>`), `getEpoch()`,
  `getParentLeaseKey()`.

**Spec 03 — CREATE wiring:**
- `SMB2CreateRequest` 12-arg constructor taking `SMB2OplockLevel requestedOplockLevel`
  + `List<SMB2CreateContext> createContexts`.
- `SMB2CreateResponse.getOplockLevel()` (`SMB2OplockLevel`) and
  `getLeaseResponseContext()` → decoded `RqLs` response context or `null`.
- `Share.createFile(...)` is the call site spec 03 already taught to forward an
  oplock level + context list (or that spec 05 extends — see §4.2). This spec adds a
  variant of `createFile`/`openFileId` that accepts the lease context + oplock level
  and returns the full `SMB2CreateResponse` (not just the `SMB2FileId`) so the
  granted lease can be read back.

**Spec 04 — negotiate gating:**
- `ConnectionContext.supportsDirectoryLeasing()` (`ConnectionContext.java:199`) —
  true only when an SMB 3.x dialect was negotiated AND the server advertised
  `SMB2_GLOBAL_CAP_DIRECTORY_LEASING (0x20)`. Reachable from the share via
  `session.getConnection().getConnectionContext()` (`Session.java:282`,
  `Connection.java:314`).

Fed forward:
- **Spec 06** resolves an inbound break's `LeaseKey` via
  `LeaseManager.lookup(leaseKey)` → `LeaseEntry`, then mutates granted state/epoch
  and drives invalidate/ack/close. So `LeaseManager` MUST be reachable from the
  break-handler chain (it is owned by the `Connection`).
- **Spec 07** stores/serves a `LeasedDirectoryCache` on the `LeaseEntry`
  (and/or on the returned `Directory`); §3.4 reserves the slot.

---

## 3. Design

### 3.1 Directory leases are V2, RH-requested

Per [MS-SMB2] (`docs/ms-smb2-lease-spec.md` §0/§3): a directory lease requires the
**V2** `RqLs` context (SMB 3.x only) and `RequestedOplockLevel = LEASE (0xFF)`.
Apple requests `HANDLE_CACHING | FILE_READ_DATA` for dirs
(`docs/apple-smbclient-leases.md` §3); the operative client request in lease-state
terms is **`READ_CACHING | HANDLE_CACHING` (RH)**. The server **always strips W**
for directories and grants **R or RH** ([MS-SMB2] 3.3.5.9.11). We request RH and
accept whatever the server grants (RH preferred; R acceptable).

### 3.2 `LeaseManager` / `LeaseEntry` model

```
Connection ──owns──▶ LeaseManager
                        └─ ConcurrentHashMap<LeaseKey, LeaseEntry>
                        └─ ConcurrentHashMap<String, LeaseKey>   (path → minted key)

LeaseEntry { LeaseKey leaseKey; LeaseKey parentLeaseKey;   // nullable
             Set<SMB2LeaseState> requestedState;
             volatile Set<SMB2LeaseState> grantedState;    // updated on response/break
             volatile int epoch;
             String path;                                  // share-relative, normalized
             volatile SMB2FileId fileId;                   // set once the open succeeds
             volatile boolean granted;
             /* spec 07: LeasedDirectoryCache cache; */ }
```

- **Ownership = per-Connection.** A `LeaseKey` is connection-global (the break
  notification carries no tree/session id — `SessionId=0, TreeId=0`), so the table
  must live where any inbound break can find it: on the `Connection`. (Per-Session
  would not see breaks that the receive thread dispatches before session context is
  known.) Construct it in `Connection` and expose `Connection.getLeaseManager()`.
- **Two maps.** The primary `LeaseKey → LeaseEntry` is what spec 06 looks breaks up
  in. The secondary `path → LeaseKey` enforces the per-node key (§3.3) and lets the
  open flow find the **parent** directory's key (§3.4).
- **Thread-safety.** Use `ConcurrentHashMap`; `grantedState`/`epoch`/`fileId`/
  `granted` are `volatile` because the receive thread (break handler, spec 06) and
  the caller thread both touch a `LeaseEntry`.

### 3.3 Lease-key minting (per node, reused)

A `LeaseKey` is minted **once per directory path** and reused for the lifetime of
that node, matching Apple's per-smbnode key (`docs/apple-smbclient-leases.md` §1).
`LeaseManager.leaseKeyForPath(String path)` returns the existing key for `path` or
mints (16 random bytes) and stores one. Path is the normalized share-relative path
(use the `SmbPath.getPath()` form, lowercased/normalized consistently so the same
directory always maps to the same key — SMB paths are case-insensitive). The root
directory uses the empty-string path key.

Reuse matters because: (a) a re-open of the same directory must present the same
lease key so the server treats it as the same lease owner; (b) a child open's
`ParentLeaseKey` must equal the parent dir's *stable* key.

### 3.4 ParentLeaseKey threading

When opening directory `D` at share-relative path `p`:

1. Compute the parent path `pp` (path with the last component removed —
   `SmbPath.getParent().getPath()`, `SmbPath.java:130`). For the share root, there
   is no parent → `parentLeaseKey = null`, flag clear.
2. Look up `pp` in the registry's `path → LeaseKey` map. **Apple/[MS-SMB2] semantics:
   `ParentLeaseKey` = the parent directory's *own* lease key** — i.e. the key we
   minted/registered when *that* directory was opened with a lease
   (`docs/apple-smbclient-leases.md` §2, [MS-SMB2] §5). We only set it when the
   parent is itself a registered (leased) directory; if the parent was never opened
   with a lease, leave `parentLeaseKey = null` (flag clear) rather than minting a
   speculative parent key.
3. If a parent key is found: pass it to `SMB2LeaseCreateContext` so the V2 context
   carries `ParentLeaseKey` and `Flags |= SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET
   (0x04)`. The server uses this linkage to break the parent dir's lease when a
   child changes (spec 06's payoff).

This is *exactly* the rule the digests call out: the flag is set **iff**
`ParentLeaseKey != 0`. The child's own lease key (from §3.3) is independent of the
parent key.

### 3.5 The modified open flow (register-before-send)

```
openDirectory(path, …):
  cc = session.getConnection().getConnectionContext()
  if !cc.supportsDirectoryLeasing():
      return <today's plain open verbatim>            // fallback (no context, no entry)

  leaseKey   = leaseManager.leaseKeyForPath(path)
  parentKey  = leaseManager.leaseKeyForExistingPath(parentOf(path))   // may be null
  reqState   = EnumSet.of(READ_CACHING, HANDLE_CACHING)
  ctx        = new SMB2LeaseCreateContext(leaseKey, reqState, parentKey, /*epoch*/0)

  entry = new LeaseEntry(leaseKey, parentKey, reqState, path)
  leaseManager.register(entry)                          // *** BEFORE send ***
  try:
      resp = <createFile with oplock=LEASE, contexts=[ctx.asCreateContext()]>
  catch:
      leaseManager.unregister(leaseKey); throw

  lease = resp.getLeaseResponseContext()
  if resp.getOplockLevel() == LEASE and lease != null:
      entry.fileId       = resp.getFileId()
      entry.grantedState = lease.getLeaseState()
      entry.epoch        = lease.getEpoch()
      entry.granted      = true
  else:
      leaseManager.unregister(leaseKey)                 // server granted no lease
  return new Directory(resp.getFileId(), this, target) // attach entry → §4.3
```

The fallback branch is byte-for-byte today's behavior so non-lease servers and the
existing test matrix are unaffected.

---

## 4. Files to add / change

### 4.1 ADD `src/main/java/com/hierynomus/mssmb2/LeaseManager.java`

New class (package `com.hierynomus.mssmb2` per `00-overview.md` "Break handling"
list, which places `LeaseManager` alongside the lease primitives so both the
`mssmb2` break handler and the `smbj` share layer can use it). Holds the two maps
(§3.2). API in §5.1.

> If spec 06's break handler ends up in `com.hierynomus.smbj.connection`, place
> `LeaseManager` in `com.hierynomus.smbj.connection` instead to avoid a layering
> cycle — `00-overview.md` lists it under both "Break handling" packages. Pick the
> package that 06 imports; default to `com.hierynomus.smbj.connection` since it is
> owned by `Connection` and references `SMB2FileId`/`LeaseKey` only. **This spec
> assumes `com.hierynomus.smbj.connection.LeaseManager`.**

### 4.2 ADD `src/main/java/com/hierynomus/smbj/connection/LeaseEntry.java`

New value/state holder (§3.2 fields, §5.2).

### 4.3 CHANGE `src/main/java/com/hierynomus/smbj/connection/Connection.java`

- Add field `private final LeaseManager leaseManager = new LeaseManager();`
  (alongside the other per-connection state).
- Add accessor `public LeaseManager getLeaseManager() { return leaseManager; }`
  next to `getConnectionContext()` (`Connection.java:314`).

### 4.4 CHANGE `src/main/java/com/hierynomus/smbj/share/Share.java`

Add a lease-aware create entry point next to `createFile` (`Share.java:151-158`).
`createFile` today builds the request and returns the `SMB2CreateResponse`; add an
overload (or extend per spec 03) that forwards an `SMB2OplockLevel` + a
`List<SMB2CreateContext>` to the spec-03 12-arg `SMB2CreateRequest` constructor and
returns the response so the caller can read the granted lease:

```java
// new — used by DiskShare.openDirectory's lease path
SMB2CreateResponse createFile(SmbPath path, SMB2ImpersonationLevel impersonationLevel,
        Set<AccessMask> accessMask, Set<FileAttributes> fileAttributes,
        Set<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition,
        Set<SMB2CreateOptions> createOptions,
        SMB2OplockLevel oplockLevel, List<SMB2CreateContext> createContexts) {
    SMB2CreateRequest cr = new SMB2CreateRequest(dialect, sessionId, treeId,
            impersonationLevel, accessMask, fileAttributes, shareAccess,
            createDisposition, createOptions, path, oplockLevel, createContexts);
    return sendReceive(cr, "Create", path, getCreateStatusHandler(), transactTimeout);
}
```

The existing 7-arg `createFile` (`:151`) stays and delegates with `NONE` + empty
list (keeps `createFileAndResolve` at `DiskShare.java:75` and all other callers
unchanged). Expose a getter for the connection's `LeaseManager` to `DiskShare`
via the session: `session.getConnection().getLeaseManager()` (no Share change
needed beyond reaching it — `Session.getConnection()` is `Session.java:282`).

### 4.5 CHANGE `src/main/java/com/hierynomus/smbj/share/DiskShare.java`

This is the heart of the milestone.

- **`openDirectory` (`DiskShare.java:144-160`)** keeps its public signature. After
  computing `actualCreateOptions`/`actualAttributes` (`:145-150`), branch:
  - If `!getConnectionContext().supportsDirectoryLeasing()` → call the existing
    `open(...)` (`:152`) exactly as today and return.
  - Else call a new private `openDirectoryWithLease(path, accessMask,
    actualAttributes, shareAccesses, createDisposition, actualCreateOptions)`
    (§3.5 / §5.3).
- **ADD `private Directory openDirectoryWithLease(...)`** implementing §3.5: mint
  key, thread parent key, build `SMB2LeaseCreateContext`, **register the
  `LeaseEntry` before send**, call the new lease-aware create path through the
  resolve machinery, fold granted state into the entry (or unregister), build the
  `Directory`.
  - Reuse the resolve plumbing: the cleanest seam is to thread the oplock level +
    contexts through `createFileAndResolve` (`DiskShare.java:74-98`) /
    `resolveAndCreateFile` (`:100-119`) so DFS/symlink resolution still works.
    Either add overloads carrying `(oplockLevel, contexts)` or stash them on a small
    request-scoped holder; do **not** duplicate the resolve loop. Register the entry
    once, *before* the first `createFile` send, against the *original* path's lease
    key.
- **Helper `getConnectionContext()`** on `DiskShare`/`Share`:
  `return session.getConnection().getConnectionContext();` (mirror the existing
  `session` field usage at `DiskShare.java:122`).
- **Attach the entry to the `Directory`.** Add an optional `LeaseEntry` to
  `Directory` (see §4.6) so spec 07's cache and spec 06's close-on-break can find
  the granted lease from the handle. `getDiskEntry` (`DiskShare.java:132-139`)
  builds the `Directory`; the lease path uses the richer constructor.

### 4.6 CHANGE `src/main/java/com/hierynomus/smbj/share/Directory.java`

- Add an optional `private final LeaseEntry leaseEntry;` (nullable) and a second
  package-private constructor `Directory(SMB2FileId, DiskShare, SmbPath, LeaseEntry)`
  delegating to the existing one (`Directory.java:37-39`) and setting the field. The
  existing constructor passes `null`.
- Add `public LeaseEntry getLeaseEntry()` (nullable) so 06/07 can reach the granted
  state + cache slot. No behavior change to `list()`/`iterator()` in this milestone
  (spec 07 will consult `leaseEntry` before issuing `QUERY_DIRECTORY`).

> `DiskEntry`/`Open` (`Open.java:34-47`) hold `fileId` + `share` + `name`; the lease
> entry is the only new state a leased `Directory` needs. Keeping it on `Directory`
> (not `Open`) avoids touching the file path.

---

## 5. Class / method sketches (signatures + logic, not full impl)

### 5.1 `LeaseManager`

```java
public class LeaseManager {
    private final ConcurrentMap<LeaseKey, LeaseEntry> byKey   = new ConcurrentHashMap<>();
    private final ConcurrentMap<String,  LeaseKey>  byPath    = new ConcurrentHashMap<>();

    /** Stable per-node key: mint once per normalized path, reuse thereafter. */
    public LeaseKey leaseKeyForPath(String path) {
        String k = normalize(path);
        return byPath.computeIfAbsent(k, p -> LeaseKey.generate());
    }

    /** Parent-key lookup: only returns a key if that path was already leased. */
    public LeaseKey leaseKeyForExistingPath(String path) {
        return byPath.get(normalize(path));            // null if parent not leased
    }

    /** Register BEFORE sending the CREATE (break can race the response). */
    public void register(LeaseEntry entry) {
        byKey.put(entry.getLeaseKey(), entry);
        byPath.putIfAbsent(normalize(entry.getPath()), entry.getLeaseKey());
    }

    public LeaseEntry lookup(LeaseKey key)   { return byKey.get(key); }      // spec 06
    public void unregister(LeaseKey key)     { byKey.remove(key); }          // keep byPath: key is stable

    private static String normalize(String path) {
        return path == null ? "" : path.replace('/', '\\').toLowerCase(Locale.ROOT);
    }
}
```

Notes: `unregister` drops the granted `LeaseEntry` but MAY keep the `byPath` key so
a re-open reuses the same node key (§3.3). `leaseKeyForPath` mints into `byPath`
even before `register`, which is fine — the parent lookup only treats a path as
"leased" if a `LeaseEntry` exists; consider having `leaseKeyForExistingPath` consult
`byKey` rather than `byPath` if you want strict "has a live lease" semantics. (Test
F pins the chosen semantics.)

### 5.2 `LeaseEntry`

```java
public class LeaseEntry {
    private final LeaseKey leaseKey;
    private final LeaseKey parentLeaseKey;            // nullable
    private final Set<SMB2LeaseState> requestedState;
    private final String path;
    private volatile Set<SMB2LeaseState> grantedState = EnumSet.noneOf(SMB2LeaseState.class);
    private volatile int epoch;
    private volatile SMB2FileId fileId;
    private volatile boolean granted;
    // spec 07: private volatile LeasedDirectoryCache cache;

    public LeaseEntry(LeaseKey leaseKey, LeaseKey parentLeaseKey,
                      Set<SMB2LeaseState> requestedState, String path) { ... }

    // getters; setGrantedState/ setEpoch / setFileId / setGranted (called from open + spec 06)
}
```

### 5.3 `DiskShare.openDirectoryWithLease`

```java
private Directory openDirectoryWithLease(String path, Set<AccessMask> accessMask,
        Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses,
        SMB2CreateDisposition disposition, Set<SMB2CreateOptions> options) {

    LeaseManager lm = session.getConnection().getLeaseManager();
    SmbPath full    = new SmbPath(smbPath, path);
    String  rel     = full.getPath();                       // share-relative
    LeaseKey key       = lm.leaseKeyForPath(rel);
    LeaseKey parentKey = lm.leaseKeyForExistingPath(full.getParent().getPath());  // §3.4

    Set<SMB2LeaseState> req = EnumSet.of(SMB2LeaseState.READ_CACHING,
                                         SMB2LeaseState.HANDLE_CACHING);
    SMB2LeaseCreateContext ctx = new SMB2LeaseCreateContext(key, req, parentKey, 0);

    LeaseEntry entry = new LeaseEntry(key, parentKey, req, rel);
    lm.register(entry);                                      // *** BEFORE send ***
    SMB2CreateResponse resp;
    try {
        resp = resolveAndCreateFileWithLease(full, accessMask, attributes,
                 shareAccesses, disposition, options,
                 SMB2OplockLevel.LEASE, Collections.singletonList(ctx.asCreateContext()));
    } catch (RuntimeException e) {
        lm.unregister(key);
        throw e;
    }

    SMB2LeaseResponseContext lease = resp.getLeaseResponseContext();
    if (resp.getOplockLevel() == SMB2OplockLevel.LEASE && lease != null) {
        entry.setFileId(resp.getFileId());
        entry.setGrantedState(lease.getLeaseState());
        entry.setEpoch(lease.getEpoch());
        entry.setGranted(true);
    } else {
        lm.unregister(key);                                 // no lease granted
        entry = null;
    }
    return new Directory(resp.getFileId(), this, full, entry);
}
```

`resolveAndCreateFileWithLease` is the spec-03/§4.4 lease-aware twin of
`resolveAndCreateFile` (`DiskShare.java:100`) that forwards `(oplockLevel,
contexts)` into the new `Share.createFile` overload while preserving DFS/symlink
resolution. The `LeaseEntry` is registered **once**, against the original path's
key, before any send.

---

## 6. TDD tests (failing-first)

Write these first and watch them fail, then implement §4/§5 to green.

### 6.1 Unit — `LeaseManagerSpec.groovy` (new, offline)

Place under `src/test/groovy/com/hierynomus/smbj/connection/`. `LeaseManager` and
`LeaseEntry` are plain objects (no socket), fully mockable.

**Test E — register-before-send: entry is resolvable by key immediately.**
```
given:  def lm = new LeaseManager()
        def key = lm.leaseKeyForPath("subdir")
        def entry = new LeaseEntry(key, null, EnumSet.of(READ_CACHING, HANDLE_CACHING), "subdir")
when:   lm.register(entry)            // simulates the pre-send registration
then:   lm.lookup(key) == entry       // a break arriving NOW would resolve
```

**Test F — parent-key threading: child's parent key == parent dir's own key.**
```
given:  def lm = new LeaseManager()
        def rootKey = lm.leaseKeyForPath("")            // root opened with a lease
        lm.register(new LeaseEntry(rootKey, null, RH, ""))
when:   def childParent = lm.leaseKeyForExistingPath(new SmbPath("h","s","sub").getParent().getPath())
then:   childParent == rootKey                          // child threads root's key
        // and an unleased parent yields null:
        lm.leaseKeyForExistingPath("never-opened") == null
```

**Test G — per-node key reuse + unregister keeps the node key.**
```
expect: lm.leaseKeyForPath("dir") == lm.leaseKeyForPath("DIR")   // case-insensitive, stable
        def k = lm.leaseKeyForPath("dir")
        lm.register(new LeaseEntry(k, null, RH, "dir"))
        lm.unregister(k)
        lm.lookup(k) == null
        lm.leaseKeyForPath("dir") == k                            // node key survives
```

**Test H — granted-state fold (mock create response).** Mock an `SMB2CreateResponse`
returning `getOplockLevel() == LEASE` and a `SMB2LeaseResponseContext` with
`leaseState = {R,H}`, `epoch = 1`; drive the response-handling branch of §5.3
(extract it to a small testable method, e.g. `applyLeaseResponse(entry, resp)`) and
assert `entry.granted`, `entry.grantedState == {R,H}`, `entry.epoch == 1`,
`entry.fileId == resp.fileId`. A response with `OplockLevel = NONE` / null lease
must `unregister` and leave `entry.granted == false`.

### 6.2 Integration — `DirectoryLeaseIT.java` (new, live vs .12)

Model on `LiveSambaSmokeIT` (`src/it/java/com/hierynomus/smbj/smoke/`): same env
helpers (`SMBJ_IT_HOST=<smb-host>`, port 1445, `smbj`/`changeit`,
`testshare`), excluded from CI by default, run with
`SMBJ_IT_HOST=<smb-host> ./gradlew integrationTest --tests "*DirectoryLeaseIT"`.
Also provide a Testcontainers variant keyed off `SambaContainer`
(`src/it/java/com/hierynomus/smbj/testcontainers/SambaContainer.java`) once the
bundled image is bumped to ≥4.22 (spec 08); the live `.12` test is the primary
acceptance gate for this milestone.

**Test I — root open is granted an RH directory lease.**
```
assume: conn.getConnectionContext().supportsDirectoryLeasing()  // precondition (smoke IT proved it)
when:   Directory root = share.openDirectory("",
              EnumSet.of(GENERIC_READ), null,
              EnumSet.of(FILE_SHARE_READ, FILE_SHARE_WRITE),
              FILE_OPEN, EnumSet.noneOf(SMB2CreateOptions.class));
then:   LeaseEntry e = root.getLeaseEntry();
        assertThat(e).isNotNull();
        assertThat(e.isGranted()).isTrue();
        // server grants RH (R+H); at minimum R must be present, W never:
        assertThat(e.getGrantedState()).contains(READ_CACHING, HANDLE_CACHING);
        assertThat(e.getGrantedState()).doesNotContain(WRITE_CACHING);
        // and the registry resolves the key (register-before-send held):
        assertThat(conn.getLeaseManager().lookup(e.getLeaseKey())).isSameAs(e);
```
(If the server only grants R for the root, relax to `contains(READ_CACHING)` and
log the granted set; the spec target is RH.)

**Test J — subdir open threads the parent (root) lease key + sets the flag.**
```
given:  Directory root = share.openDirectory("", …);              // leased, mints root key
        LeaseKey rootKey = root.getLeaseEntry().getLeaseKey();
when:   Directory sub  = share.openDirectory("subdir", …);        // child of root
then:   LeaseEntry se = sub.getLeaseEntry();
        assertThat(se.getParentLeaseKey()).isEqualTo(rootKey);     // ParentLeaseKey == root's own key
        assertThat(se.isGranted()).isTrue();
```
To assert the wire-level `PARENT_LEASE_KEY_SET (0x04)` flag + the 52-byte V2 layout
deterministically (offline), add a request-serialization unit case (reuse spec 03's
`SMB2CreateRequestSpec` harness): build the open with a non-null parent key and
assert the emitted `RqLs` context is 52 bytes, `Flags == 0x04`, and `ParentLeaseKey`
bytes equal the root key — the live IT confirms the server *accepts/echoes* it; the
unit case confirms we *send* it.

**Test K — fallback when leasing unsupported (offline/unit).** With a mocked
`ConnectionContext.supportsDirectoryLeasing() == false`, `openDirectory` must take
the plain-`open` path: no `LeaseEntry` on the returned `Directory`
(`getLeaseEntry() == null`) and nothing registered in the `LeaseManager`.

---

## 7. Acceptance criteria

1. A `LeaseManager` (keyed `LeaseKey → LeaseEntry`, plus `path → LeaseKey`) is owned
   per-`Connection` and reachable via `Connection.getLeaseManager()`. `LeaseEntry`
   holds `{leaseKey, parentLeaseKey, requestedState, grantedState, epoch, path,
   fileId, granted}` with thread-safe (volatile) mutable state.
2. A directory `LeaseKey` is minted **once per normalized path** and **reused**
   (case-insensitive, survives `unregister`) — Tests E/G.
3. `DiskShare.openDirectory`, when `supportsDirectoryLeasing()` is true, sends a
   CREATE with `RequestedOplockLevel = LEASE (0xFF)` carrying a **V2 `RqLs`** context
   with `LeaseState = READ_CACHING|HANDLE_CACHING`, the minted lease key, and — when
   the parent directory is itself leased — `ParentLeaseKey = parent dir's own lease
   key` plus `Flags = PARENT_LEASE_KEY_SET (0x04)` — Tests J + the V2 serialization
   case.
4. The `LeaseEntry` is **registered in the `LeaseManager` before the CREATE is
   sent**, and resolvable by `LeaseKey` at send time — Test E and the live-IT
   `lookup(...).isSameAs(entry)` assertion (Test I). On a granted response the entry
   is updated with `grantedState`/`epoch`/`fileId`/`granted=true`; on no-lease /
   failure it is unregistered — Test H.
5. When `supportsDirectoryLeasing()` is false, `openDirectory` falls back to today's
   plain `open(...)` byte-for-byte: no context, oplock `NONE`, no registry entry, no
   `LeaseEntry` on the `Directory` — Test K. All existing tests stay green
   (`./gradlew clean build`), Java 8 target.
6. Live vs `.12`: opening `testshare` root yields a granted directory lease whose
   state contains `READ_CACHING` (target RH, never `WRITE_CACHING`); opening
   `subdir` yields a `LeaseEntry` whose `parentLeaseKey` equals the root directory's
   own lease key — Tests I + J.
```
