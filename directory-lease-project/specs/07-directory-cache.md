# 07 — Client-Side Directory-Enumeration Cache (`LeasedDirectoryCache`)

> Milestone 7 of `00-overview.md`. Depends on spec 05 (`DiskShare.openDirectory`
> requests an RH directory lease; `LeaseManager` / `LeaseEntry` lease table;
> register-before-send) and spec 06 (inbound break routing → invalidate hook).
> This is where the **performance win** lives: a second `list()` on an unchanged
> leased directory serves from memory with **zero** `QUERY_DIRECTORY` round-trip.
>
> **Correctness over speed — the load-bearing invariant.** We MUST NEVER serve an
> enumeration that was cached *before a lease break we have already observed* for
> that directory. The cache is authoritative only while a valid (granted,
> un-broken) RH/H directory lease is held; the instant a break is seen (spec 06)
> the entry is evicted, so the next `list()` does a real wire query. Fast second.

All paths below are relative to `smbj/` unless noted. Line anchors are from the
current checkout (read-only inspection performed; no source modified by this spec).

---

## 1. Purpose & scope

Today smbj caches **nothing**. `Directory.DirectoryIterator` re-issues a fresh
`QUERY_DIRECTORY` (with `SMB2_RESTART_SCANS`) on *every* `list()` /
`iterator()` call (`share/Directory.java:148`, `:179-208`), and the convenience
path `DiskShare.list(path, …)` opens the directory, enumerates, and closes it on
*every* call (`share/DiskShare.java:258-269`). With a directory lease granted
(spec 05) the server has promised to push a break before anything in that
directory changes, so re-querying is pure waste — exactly the win Apple's smbfs,
Windows, and Samba ≥4.22 realize.

This spec adds `LeasedDirectoryCache`: a per-leased-directory store of the **last
full enumeration result**, keyed by `(path, informationClass, searchPattern)`,
populated from a real `QUERY_DIRECTORY` and served on repeat `list()` **only while
a valid RH/H lease is held**, and evicted the moment a break is seen for that
lease (spec 06) or the lease is downgraded/lost.

In scope:

- `LeasedDirectoryCache` — the store: populate / serve / evict, thread-safe.
- Integration at the `DiskShare.list(path, …)` choke point
  (`share/DiskShare.java:258-269`) — consult cache before opening + enumerating.
- The break/downgrade → evict wiring onto spec 05's `LeaseEntry` and spec 06's
  break hook.
- The HANDLE-caching interaction (Apple): keep the directory handle open while a
  cache entry is live; closing it drops the entry.

**The explicit correctness invariant (restated, normative):**

> For a given lease key `L`, let `B(L)` be the set of break-notification arrivals
> the client has processed for `L`. A cached enumeration `E` produced at time
> `t_E` may be served at time `t_S` **only if** no break in `B(L)` arrived in
> `(t_E, t_S]`. Equivalently: any break for `L` evicts every entry under `L`
> *before* it can be served again. A stale read across a break is a **correctness
> failure**, not a performance regression — the IT in §6(b) exists to catch it.

Out of scope (deferred / non-goals per `00-overview.md`):

- Caching listings for directories with **no** granted lease (we bypass the cache;
  the real query always runs — never a time-based guess).
- Lease **upgrade** optimisation; caching of file *data*; partial/incremental
  enumeration deltas. We cache whole listings only.
- Caching non-default `searchPattern` listings — **bypassed by default**, see §3.4.

---

## 2. Dependencies (specs 05, 06)

These APIs MUST exist (green) before implementing §4. Names follow
`00-overview.md` "Naming & package conventions". Where spec 05/06 are not yet
merged, §5 isolates the surface behind a tiny interface so this milestone can be
unit-tested against a mock `LeaseEntry` (see §6.3).

**Spec 05 — `com.hierynomus.smbj.share.LeaseManager`** (the lease table):
```
LeaseEntry getByPath(SmbPath path)        // resolve a leased dir by its path, or null
LeaseEntry getByLeaseKey(LeaseKey key)    // resolve a leased dir by lease key (break path)
boolean    supportsDirectoryLeasing()     // == ConnectionContext.supportsDirectoryLeasing()
```
Reachable from a `DiskShare` via its `TreeConnect`/`Session`/`Connection`
(the lease table is per-connection; spec 05 owns its placement). For this spec
the only requirement is that `DiskShare.list` can obtain the `LeaseManager`.

**Spec 05 — `com.hierynomus.smbj.share.LeaseEntry`** (the leased-directory record):
```
LeaseKey       getLeaseKey();
SmbPath        getPath();
SMB2FileId     getFileId();              // the OPEN directory handle (kept open while H held)
long           getLeaseState();          // current granted state bitmask (SMB2LeaseState)
boolean        isReadHandleGranted();    // SMB2LeaseState.isReadHandle(getLeaseState()) — RH usable
boolean        isBroken();               // a break has been observed for this entry
LeasedDirectoryCache getCache();         // the cache hangs off the lease entry (this spec adds it)
```
> The cache **hangs off the `LeaseEntry`** (overview milestone-7 row: "the cache
> hangs off the lease entry"). One `LeasedDirectoryCache` per leased directory; its
> lifetime == the lease entry's. When spec 05 removes the entry from the table (on
> close / break / downgrade-to-none) the cache dies with it.

**Spec 06 — break hook.** Spec 06's `SMB2LeaseBreakPacketHandler` resolves the
break to a `LeaseEntry` via `getByLeaseKey(...)`, applies the epoch-delta rule,
marks the entry broken, and **invalidates caches**. This spec defines the exact
call it makes:
```
leaseEntry.getCache().invalidateAll();   // Apple's d_changecnt++ / name-cache purge equivalent
```
which spec 06 invokes **synchronously, before** it closes the handle / sends the
ack (mirrors Apple: `smbfs_handle_dir_lease_break` bumps `d_changecnt` and
`cache_purge(vp)` immediately, then the lease thread closes the deferred handle —
`docs/apple-smbclient-leases.md` §5). Synchronous-before-close is what makes the
invariant hold: the cache is dead before any subsequent `list()` can observe it.

**Spec 02 — `com.hierynomus.mssmb2.SMB2LeaseState`:** `isReadHandle(long)` (RH ==
`(s & 0x3) == 0x3`) and `SMB2_LEASE_HANDLE_CACHING (0x02)` for the H-bit downgrade
check (§3.5).

---

## 3. Design

### 3.1 Cache key

A cache entry is keyed by the triple:

```
CacheKey = ( SmbPath path , FileInformationClass informationClass , String searchPattern )
```

- `path` — the directory path as passed to `DiskShare.list(path, …)`, normalised
  to the same `SmbPath` the lease table is keyed on (spec 05). The lease entry is
  already resolved per-path, so within one `LeasedDirectoryCache` instance the
  `path` is effectively constant; we still include it in the key so the type is
  self-describing and a single shared cache (if ever flattened) stays correct.
- `informationClass` — derived from the `Class<I extends
  FileDirectoryQueryableInformation>` argument via
  `FileInformationFactory.getDecoder(informationClass).getInformationClass()`
  (the same value `DirectoryIterator` computes at `Directory.java:190`). Two
  listings that decode to different `FileInformationClass`es are **different
  cache entries** — their wire results differ.
- `searchPattern` — see §3.4. Default (`null`/empty == "all files") is cacheable;
  any non-default pattern **bypasses** the cache.

`CacheKey` needs `equals`/`hashCode` over the triple (`SmbPath` already has value
equality; `FileInformationClass` is an enum; `searchPattern` a `String`).

### 3.2 What is stored

The stored value is the **fully materialised listing** — the same
`List<I extends FileDirectoryQueryableInformation>` that `Directory.list(...)`
would return after draining its iterator. We cache the decoded result list (not
the raw `QUERY_DIRECTORY` output buffers): it is immutable-by-convention, directly
returnable, and decoupled from wire-paging details.

```
CacheValue = List<? extends FileDirectoryQueryableInformation>   // unmodifiable snapshot
```

Stored as an unmodifiable copy so a caller mutating the returned list cannot
corrupt a shared cache entry. (The generic erasure is handled by an unchecked cast
at the typed `serve` boundary — see §5; the runtime element type is guaranteed by
the `informationClass` component of the key.)

### 3.3 When populated / when served / when invalidated

| Event | Action |
|-------|--------|
| `list(path)`, lease **not** held / not RH | **bypass**: real `QUERY_DIRECTORY`, return result, **do not** populate. |
| `list(path)`, RH lease held, **miss** | real `QUERY_DIRECTORY`, **populate** entry under the key, return. |
| `list(path)`, RH lease held, **hit** | **serve from cache** — no `open`, no `QUERY_DIRECTORY`, no `close`. |
| break for lease `L` (spec 06) | `getCache().invalidateAll()` — evict **all** keys under `L`, synchronously, before close/ack. |
| lease downgrade losing H (§3.5) | `invalidateAll()` — drop cache (handle no longer safe to keep / trust). |
| local mutation via this handle (mkdir/rm/rename under the leased dir) | `invalidateAll()` (optional hardening, §3.6). |
| lease entry removed / handle closed | cache dies with the entry (GC). |

Populate happens **only when a usable lease is held** — never on the bypass path.
This is deliberate: a populated entry without a live lease has no break to protect
it and could go stale silently. No lease ⇒ no cache, full stop.

### 3.4 searchPattern & informationClass variations (the safe default)

- **informationClass:** cached **per-class** (it is part of the key). Safe and
  precise — different classes are different wire results, never conflated.
- **searchPattern:** the safe default is **cache only the "list everything" case**
  (`searchPattern == null` or empty), and **bypass the cache for any non-null /
  non-empty pattern** (always do a real `QUERY_DIRECTORY`, never populate).

  Rationale: a filtered listing is a *subset* of the full enumeration; caching
  subsets risks (a) serving a stale subset after the dir changed in a way the
  pattern would now match/exclude, and (b) cache-key blow-up across arbitrary
  patterns. Bypassing patterned queries keeps the invariant trivially true for
  them while still delivering the win on the overwhelmingly common
  `list()` / `list(path)` / `list(path, class)` calls (all of which pass
  `searchPattern == null` — see `DiskShare.java:231-251`, `Directory.java:46-56`).

  `LeasedDirectoryCache.isCacheable(searchPattern)` centralises this rule:
  `return searchPattern == null || searchPattern.isEmpty();`. (Future work could
  cache popular patterns under the same key scheme; out of scope here.)

### 3.5 Interaction with HANDLE caching (Apple model) — handle stays open

Per `docs/apple-smbclient-leases.md` §0/§3: the **H (handle)** lease bit is what
lets the client keep the directory handle open and trust its cached enumeration
(`vnop_close` keeps the dir open only while
`GRANTED && (lease_state & HANDLE_CACHING)`, ref §3 of the digest). The cache and
the open handle are therefore coupled:

- A cache entry is valid **iff** the owning `LeaseEntry` still holds the directory
  **open** with **RH** granted. Spec 05 keeps that `SMB2FileId` open for the life
  of the lease (deferred close); this cache rides on it.
- **`DiskShare.list(path)` must NOT close the leased handle.** Today's path opens a
  fresh handle and `closeSilently()`s it in a `finally` (`DiskShare.java:259-268`).
  On a cache **hit** we never open at all. On a cache **miss with a lease held** we
  enumerate via the **already-open leased handle** (`leaseEntry.getFileId()`) and
  do **not** close it (the lease owns its lifetime). Only the **bypass** (no-lease)
  path retains the open-enumerate-close behaviour exactly as today.
- **On handle close / lease release** (lease entry torn down): the cache is
  evicted (`invalidateAll()` then drop). Closing the deferred handle is also
  spec 06's implicit break-ack; the cache must already be invalid by then (the
  break hook in §2 evicts *before* close).

### 3.6 Lease downgrade ⇒ drop cache

If a break **downgrades** rather than fully revokes (e.g. RH → R, losing the H
bit), Apple drops the deferred-close ability for that node. We mirror it: any
transition that **loses the H bit** (`(newState & HANDLE_CACHING) == 0` while old
had it) MUST `invalidateAll()` — without H we may not keep the handle open, so we
cannot trust the cache. Losing the **R** bit (read caching) likewise drops the
enumeration cache. In practice a directory break is to `NONE` (digest §5: "dir
break ⇒ expected NONE"), so the simple rule is: **any break or any
loss of R or H ⇒ evict.** Spec 06 owns the epoch-delta gating (ignore `delta ≤ 0`
stale notifications) *before* calling `invalidateAll()`, so a reordered/stale
break never needlessly drops a still-valid cache — but when in doubt, evicting is
always safe (correctness over speed).

### 3.7 Thread-safety (concurrent `list()`)

Multiple threads may call `list()` on the same path concurrently, and the receive
thread (spec 06) may fire `invalidateAll()` at any instant. Requirements:

- The backing map is a `ConcurrentHashMap<CacheKey, CacheValue>` (lock-free reads).
- `invalidateAll()` = `map.clear()` (atomic enough for our purpose: any get that
  races a clear either sees the old immutable value — fine, it was valid when read
  — or a miss — fine, it re-queries). Because values are immutable snapshots, a
  served list can never be mutated out from under a caller.
- **Invariant safety under races:** the break hook calls `invalidateAll()`
  *synchronously on the receive thread before the handle is closed/acked*. A
  `list()` that *began* before the break but *reads the map after* the clear gets a
  miss and re-queries (the just-closed handle forces a fresh open → correct fresh
  result). A `list()` that read a value *before* the break started was serving data
  that was valid at read time. We do **not** attempt to cache across an in-flight
  break: when in doubt, miss. There is **no** lock that a slow `list()` could hold
  to delay the break's eviction — eviction is a non-blocking `clear()`.
- We do **not** coalesce concurrent misses (no single-flight). Two racing misses
  may both query and both populate; the last write wins and both return correct
  (identical, lease-protected) data. Simplicity over a marginal dedup.

---

## 4. Files to add / change

### 4.1 NEW — `src/main/java/com/hierynomus/smbj/share/LeasedDirectoryCache.java`

New class, package `com.hierynomus.smbj.share` (overview "Directory cache"
section). Holds the `ConcurrentHashMap<CacheKey, List<…>>`, the static nested
`CacheKey`, and the populate/serve/evict/`isCacheable` API (§5). One instance per
`LeaseEntry`.

### 4.2 CHANGE — `src/main/java/com/hierynomus/smbj/share/DiskShare.java`

**Integration choke point: `list(path, informationClass, searchPattern, accessMask)`
at `DiskShare.java:258-269`.** This is the path that opens-enumerates-closes today
and the one all four public `list(...)` overloads funnel into
(`:231-233`, `:240-242`, `:249-251`, → `:258`). Restructure its body:

```java
public <I extends FileDirectoryQueryableInformation> List<I> list(
        String path, Class<I> informationClass, String searchPattern, EnumSet<AccessMask> accessMask) {

    LeaseManager leases = getLeaseManager();                 // spec 05; per-connection
    SmbPath smbPath = new SmbPath(smbPath, path);            // normalise as elsewhere in DiskShare
    LeaseEntry entry = (leases != null && leases.supportsDirectoryLeasing())
                         ? leases.getByPath(smbPath) : null;

    // (1) Cacheable + usable lease held → consult cache.
    if (entry != null && entry.isReadHandleGranted() && !entry.isBroken()
            && LeasedDirectoryCache.isCacheable(searchPattern)) {
        LeasedDirectoryCache cache = entry.getCache();
        List<I> hit = cache.serve(smbPath, informationClass, searchPattern);   // null on miss
        if (hit != null) {
            return hit;                                       // SERVED FROM CACHE — no wire I/O
        }
        // miss: enumerate via the already-open leased handle, do NOT close it.
        Directory d = entry.asDirectory();                   // wrap the open SMB2FileId (spec 05)
        List<I> result = d.list(informationClass, searchPattern);
        cache.populate(smbPath, informationClass, searchPattern, result);
        return result;
    }

    // (2) No usable lease (or non-cacheable pattern) → today's open-enumerate-close, NO populate.
    Directory d = openDirectory(path,
        accessMask == null ? of(FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_EA) : accessMask,
        null, ALL, FILE_OPEN, null);
    try {
        return d.list(informationClass, searchPattern);
    } finally {
        if (d != null) {
            d.closeSilently();
        }
    }
}
```

Notes / anchors:
- The bypass branch (2) is the **unchanged** current body (`:259-268`) verbatim —
  no behaviour change when leasing is off or no lease is held.
- `getLeaseManager()` is a new accessor wiring `DiskShare` → spec 05's table
  (per-connection); if spec 05 exposes it on `Session`/`Connection`, this is a
  one-line getter. If `LeaseManager` is unavailable (older server, leasing off),
  it returns `null` and we always take branch (2) → zero behavioural change.
- `entry.asDirectory()` wraps the lease's open `SMB2FileId` in a `Directory`
  bound to this share so we reuse `Directory.list(...)`'s paging loop
  (`Directory.java:65-72`, `:179-208`) **without** closing the handle. (Spec 05
  may already retain a `Directory` on the `LeaseEntry`; if so use it directly.)
- `SmbPath` construction mirrors how `DiskShare` builds paths elsewhere
  (the project's `new SmbPath(smbPath, path)` idiom); match the existing pattern.

### 4.3 CHANGE — `src/main/java/com/hierynomus/smbj/share/Directory.java`

No structural change to `DirectoryIterator` (`:138-214`); it remains the
wire-enumeration engine. The cache wraps `Directory.list(...)` from the outside
(§4.2). **One small allowance:** the cache hit path must be observable in tests —
ensure the real `QUERY_DIRECTORY` still flows through `share.queryDirectory(...)`
(`Directory.java:192`) so the per-share request counter / event spy in §6 sees
exactly one populate query and zero on a hit. No edit required if §4.2 routes hits
to never construct a `DirectoryIterator`.

### 4.4 CHANGE (wiring only) — spec 06's break handler

Spec 06's `SMB2LeaseBreakPacketHandler` (or `LeaseManager.handleBreak`) adds, after
epoch-delta validation and before closing the handle / sending the ack:

```java
LeaseEntry entry = leaseManager.getByLeaseKey(brokenLeaseKey);
if (entry != null) {
    entry.markBroken();                 // spec 06
    entry.getCache().invalidateAll();   // *** this spec: evict before close/ack ***
}
```

This is the single line that upholds the §1 invariant on the break path.

---

## 5. Class / method sketches (signatures + logic, not full impl)

`com.hierynomus.smbj.share.LeasedDirectoryCache`:

```java
public class LeasedDirectoryCache {

    /** (path, informationClass, searchPattern) — value-equality over all three. */
    static final class CacheKey {
        final SmbPath path;
        final FileInformationClass informationClass;
        final String searchPattern;       // normalised: null/empty only reach here (see isCacheable)
        // ctor; equals(); hashCode()  over the triple
    }

    private final ConcurrentMap<CacheKey, List<? extends FileDirectoryQueryableInformation>> entries
        = new ConcurrentHashMap<>();

    /** Default-listing only is cacheable; any real searchPattern bypasses. §3.4 */
    public static boolean isCacheable(String searchPattern) {
        return searchPattern == null || searchPattern.isEmpty();
    }

    private static FileInformationClass infoClassOf(Class<?> informationClass) {
        return FileInformationFactory.getDecoder(informationClass).getInformationClass();
    }

    /** @return the cached listing for the key, or null on miss. Lock-free read. */
    @SuppressWarnings("unchecked")
    public <I extends FileDirectoryQueryableInformation> List<I> serve(
            SmbPath path, Class<I> informationClass, String searchPattern) {
        if (!isCacheable(searchPattern)) return null;          // never serve a patterned query
        List<?> v = entries.get(new CacheKey(path, infoClassOf(informationClass), searchPattern));
        return (List<I>) v;   // runtime element type guaranteed by informationClass key component
    }

    /** Store an unmodifiable snapshot. Caller MUST hold a valid RH lease (see DiskShare §4.2). */
    public <I extends FileDirectoryQueryableInformation> void populate(
            SmbPath path, Class<I> informationClass, String searchPattern, List<I> listing) {
        if (!isCacheable(searchPattern)) return;               // never populate a patterned query
        entries.put(new CacheKey(path, infoClassOf(informationClass), searchPattern),
                    Collections.unmodifiableList(new ArrayList<>(listing)));
    }

    /** Evict everything. Called by the break/downgrade hook (spec 06) — Apple d_changecnt++. */
    public void invalidateAll() {
        entries.clear();
    }

    /** Visible-for-testing: current entry count (deterministic hit/miss assertions). */
    int size() { return entries.size(); }
}
```

Modified `DiskShare.list(...)` flow — the load-bearing logic (full body in §4.2):

```
resolve LeaseEntry by path  (only if directory leasing negotiated)
if entry has RH, not broken, and searchPattern is cacheable:
    hit = entry.cache.serve(...)                 // lock-free
    if hit != null: return hit                   // <-- ZERO round-trips
    result = entry.openDirectory.list(...)        // one QUERY_DIRECTORY via the kept-open handle
    entry.cache.populate(..., result)             // populate only because a lease protects it
    return result                                 // do NOT close the leased handle
else:
    return openDirectory(...).list(...) in finally{ closeSilently() }   // unchanged today's path
```

Break path (spec 06, §4.4): `getByLeaseKey → markBroken → cache.invalidateAll()`,
synchronously before the handle close / ack.

---

## 6. TDD tests (failing-first)

Write these before the §4 implementation and watch them fail; implement to green.
Two **integration** tests (live, vs the .12 Samba — `<smb-host>:1445`,
`smb3 directory leases = Yes`, share `testshare`, creds `smbj`/`changeit`) and
one **unit** spec. The integration tests are the ones that prove the invariant and
the win; the unit spec proves the cache mechanics in isolation.

> Deterministically observing "served from cache": add a **per-`DiskShare`
> `QUERY_DIRECTORY` request counter** (or subscribe an `SMBEventBus` spy / count
> `SMB2QueryDirectoryRequest` packets via a test `PacketReceiver`/outgoing
> interceptor). A cache **hit** must increment the counter by **0**; a **miss /
> populate** by **≥1** (one or more paging requests). This is more robust than
> wall-clock timing. (`Directory.java:192` is the single `queryDirectory` call
> site to count; spec 06 already references `SMBEventBus` for break events, so a
> lease/query event is a natural spy point — `docs/smbj-analysis.md` §4.3.4.)

### 6.1 IT (a) — two consecutive `list()` on an unchanged dir → 2nd served from cache

File: `src/it/java/com/hierynomus/smbj/DirectoryLeaseCacheIntegrationTest.java`
(extends the `IntegrationTest` / `SambaContainer` harness pattern,
`docs/smbj-analysis.md` §6; for the live .12 run, target the `testshare`).

```
given:
  connect + auth to the directory-leasing server; open testshare as DiskShare.
  install a QUERY_DIRECTORY counter (per §6 spy).
  ensure a known dir "dir07" exists with a few entries.
when:
  def first  = share.list("dir07")        // miss → opens w/ RH lease, 1+ QUERY_DIRECTORY, populates
  def qdAfterFirst = counter.get()
  def second = share.list("dir07")        // expected: HIT
then:
  qdAfterFirst >= 1                         // first call really hit the wire
  counter.get() == qdAfterFirst             // *** second call issued ZERO new QUERY_DIRECTORY ***
  second == first                           // identical listing served from cache
  leaseEntryFor("dir07").isReadHandleGranted()   // sanity: the RH lease that authorises caching
```

The `counter.get() == qdAfterFirst` assertion is the deterministic proof of a cache
hit — no second round-trip happened.

### 6.2 IT (b) — break invalidates: post-break `list()` reflects the change (NOT stale)

This is the **correctness** test for the §1 invariant.

```
given:
  connectionA: open testshare; share.list("dir07") to prime + populate the cache.
  record the QUERY_DIRECTORY counter; assert a 2nd list("dir07") is a HIT (counter unchanged)
    — establishes the cache is live and serving.
when:
  connectionB (a SECOND, independent connection/session) creates a new file
    "dir07\\added-by-B.txt"   // external mutation → server pushes a lease break to connectionA
  await break processed on A  // poll leaseEntry.isBroken() / a break-received latch (spec 06), with timeout
  def afterBreak = share.list("dir07")     // on A, AFTER the break
then:
  // cache was invalidated by the break, so this re-queried the wire:
  counter.get() > countBeforeBreak          // a real QUERY_DIRECTORY happened (NOT served stale)
  afterBreak*.fileName contains "added-by-B.txt"   // *** post-break listing reflects the change ***
  afterBreak.size() == before.size() + 1
cleanup:
  delete added-by-B.txt; close both connections.
```

If the cache were stale across the break, `afterBreak` would *omit*
`added-by-B.txt` and `counter` would be unchanged — the test fails loudly. That is
exactly the stale-read regression the invariant forbids. The break must be
**awaited** (latch/poll with timeout), not slept-on, so the test is deterministic.

### 6.3 Unit — populate / serve / evict with a mocked lease entry

File: `src/test/groovy/com/hierynomus/smbj/share/LeasedDirectoryCacheSpec.groovy`
(Spock; offline, no server). Tests the cache class in isolation; the `LeaseEntry`
is a Mockito mock so this milestone is testable even before spec 05/06 land.

```
LeasedDirectoryCache populate then serve returns the same listing:
  given: cache = new LeasedDirectoryCache(); listing = [info("a"), info("b")]
  when:  cache.populate(path, FileIdBothDirectoryInformation, null, listing)
  then:  cache.serve(path, FileIdBothDirectoryInformation, null) == listing
  and:   cache.size() == 1

miss returns null:
  expect: cache.serve(path, FileIdBothDirectoryInformation, null) == null   // empty cache

different informationClass is a different key:
  given: cache.populate(path, FileIdBothDirectoryInformation, null, [a])
  expect: cache.serve(path, FileDirectoryInformation, null) == null          // not conflated
  and:    cache.serve(path, FileIdBothDirectoryInformation, null) == [a]

non-default searchPattern is never cached (bypass):
  expect: !LeasedDirectoryCache.isCacheable("*.txt")
  and:    LeasedDirectoryCache.isCacheable(null)
  and:    LeasedDirectoryCache.isCacheable("")
  when:  cache.populate(path, FileIdBothDirectoryInformation, "*.txt", [a])
  then:  cache.serve(path, FileIdBothDirectoryInformation, "*.txt") == null  // populate was a no-op
  and:   cache.size() == 0

invalidateAll evicts everything (the break hook):
  given: cache.populate(path, FileIdBothDirectoryInformation, null, [a])
  when:  cache.invalidateAll()
  then:  cache.serve(path, FileIdBothDirectoryInformation, null) == null
  and:   cache.size() == 0

served list is an unmodifiable snapshot (caller cannot corrupt the cache):
  given: cache.populate(path, FileIdBothDirectoryInformation, null, [a, b])
  when:  cache.serve(...).add(c)
  then:  thrown(UnsupportedOperationException)   // and a fresh serve still has size 2
```

Optionally a `DiskShare.list` integration-of-logic test (Mockito) asserting: when
the mocked `LeaseEntry.isReadHandleGranted()` is true and `serve` hits, `list`
returns the cached list and **`queryDirectory` is never invoked**; when
`isBroken()` is true, `list` takes the bypass branch and re-queries.

---

## 7. Acceptance criteria

1. **Correctness invariant holds (primary).** IT (b) passes: after an external
   mutation triggers a lease break on the caching connection, the next `list()`
   reflects the change (the new entry appears) and demonstrably re-hit the wire
   (`QUERY_DIRECTORY` counter increased). No configuration of timing makes a stale
   listing observable across a break the client has processed. The break-driven
   `invalidateAll()` runs **synchronously before** the handle close / ack.
2. **Measurable request reduction on the hit path.** IT (a) passes: a second
   `list()` on an unchanged leased directory issues **zero** additional
   `QUERY_DIRECTORY` requests (counter delta == 0) and performs **no** CREATE/CLOSE
   for that listing, while returning a listing equal to the first.
3. **Lease-gated population.** A listing is cached **only** when a granted,
   un-broken **RH** directory lease is held for the path and the `searchPattern` is
   cacheable (default/empty). With leasing off, no lease, a broken/downgraded lease,
   or a non-default `searchPattern`, `DiskShare.list` takes the unchanged
   open-enumerate-close path and **never populates** the cache.
4. **Downgrade safety.** Losing the H (or R) bit, or any observed break, evicts the
   cache (`invalidateAll()`); the kept-open handle is no longer relied upon.
5. **Thread-safe.** Concurrent `list()` calls and a concurrent receive-thread
   `invalidateAll()` never produce a `ConcurrentModificationException`, never
   corrupt a served list (snapshots are unmodifiable), and never serve across a
   processed break. Backed by `ConcurrentHashMap`; eviction is a non-blocking
   `clear()`.
6. **No behavioural change when leasing is unavailable.** With directory leasing
   not negotiated (older server / config off), `DiskShare.list` is byte-for-byte
   behaviourally identical to today (branch (2) verbatim). All existing
   `SMB2DirectoryIntegrationTest` cases remain green.
7. Unit spec §6.3 green (failing-first), and the full build green
   (`./gradlew clean build`), compiling to Java 8 (`build.gradle options.release = 8`).
