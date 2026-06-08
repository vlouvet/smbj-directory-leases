# Directory-Lease Benchmark

Measures the payoff of the SMB3 directory-lease cache over a deep tree, across a 3-arm matrix.

## Matrix
| arm | server | client | what it isolates |
|-----|--------|--------|------------------|
| **new + lease ON** | Samba 4.23.8 (`.12:1445`) | `withDirectoryLeasingEnabled(true)` | the cache benefit |
| **new + lease OFF** | Samba 4.23.8 (`.12:1445`) | `withDirectoryLeasingEnabled(false)` | same server/files, no cache (clean baseline) |
| **old (lease-unaware)** | Samba 4.20.6 (`.12:1446`) | (auto-fallback, server lacks the cap) | real fallback against a pre-4.22 server |

All three target the **same** `testshare/benchtree` (bind-mounted into both containers), so it's
apples-to-apples. The old server is a second isolated container (`server/old/`), not the system smbd.

## Harness
- Tree generator: `server/gen-bench-tree.sh DEPTH FANOUT FILES_PER_DIR` (runs on `.12`, local fs).
- Runner: `smbj/src/it/java/.../DirectoryLeaseBenchmarkTest.java` — recursively walks the tree
  (cold), re-walks it (warm, best of N), and runs a name-search; reports wall-clock plus aggregate
  cache `wireEnum` (real `QUERY_DIRECTORY` enumerations) vs `cacheHits` (listings served from memory).

## Run
```bash
ssh <smb-host> 'bash /home/smbj/smbj-dirlease/server/gen-bench-tree.sh 3 5 25'   # 156 dirs, 3900 files
cd smbj
SMBJ_BENCH=1 SMBJ_IT_HOST=<smb-host> ./gradlew --no-daemon \
  integrationTest --tests "*DirectoryLeaseBenchmarkTest" --rerun-tasks
cat /tmp/smbj-bench.txt
```

## Result (2026-06-07, tree = 156 dirs / 3900 files, LAN)
```
arm                        dirs   cold(ms)   warm(ms) search(ms)     wireEnum  cacheHits
new + lease ON              156        636          1          1          156        624
new + lease OFF             156        528        492        505            0          0
old (4.20, no lease)        156        595        702        522            0          0
```

### Reading it
- **Repeated listing / search collapse from ~500 ms to ~1 ms with leases on** — every one of the
  156 directory listings is served from the client cache (`cacheHits` accrues over the warm + search
  rounds; `wireEnum` stays at 156 = the single cold enumeration per directory). That's a **~500×**
  reduction in wall-clock on the warm path, and **156 → 0** `QUERY_DIRECTORY` round-trips per
  re-walk.
- **Lease OFF / old server** re-walks stay at full cost (~500–700 ms) because every `list()` hits
  the wire — confirming the win is the lease cache, not the newer Samba build.
- **Cold walk** is marginally slower with leases on (636 vs 528 ms): the first pass also acquires a
  lease and keeps the handle open per directory. Negligible next to the warm-path win, and a one-time
  cost.

### Scaling — depth 5, 1,365 dirs / 10,920 files (`gen-bench-tree.sh 5 4 8`)
```
arm                        dirs   cold(ms)   warm(ms) search(ms)     wireEnum  cacheHits
new + lease ON             1365       4196          2          2         1365       5460
new + lease OFF            1365       4594       4767       4916            0          0
old (4.20, no lease)       1365       4719       4605       4820            0          0
```
The win **grows with tree size**: a re-walk/search drops from **~4,800 ms to ~2 ms (~2,400×)** — vs
~500× on the 156-dir tree. The warm time stays flat (~1–2 ms, a memory lookup per dir) while the
no-cache arms pay `dirs × RTT` every time, so the **absolute** time saved per re-walk scales linearly
with the number of directories (0.5 s saved at 156 dirs → ~4.8 s at 1,365 dirs). `cacheHits` = 5,460
= 1,365 dirs × 4 re-walks (3 warm + 1 search); `wireEnum` = 1,365 = one enumeration per dir on the
cold pass. 1,365 directory handles were held open with no resource issues — the implementation scales.
(Cold is comparable across arms; here lease-ON cold even edged ahead, within run-to-run noise.)

### Caveats / honest notes
- This is a fast LAN; absolute savings scale with **round-trip latency** — over Wi-Fi / VPN / WAN
  each eliminated round-trip saves the full RTT, so the gap widens dramatically.
- Wall-clock has noise; the deterministic figure is `wireEnum`/`cacheHits` (requests eliminated).
- The current cache keeps a directory handle open per cached dir (Apple's model) and does not yet
  LRU-evict; fine for hundreds of dirs, a future hardening for very large trees.
- A single-user repeated-listing/search workload is exactly where this shines; a one-shot cold walk
  sees no benefit (and a tiny cost).
