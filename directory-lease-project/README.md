# smbj Directory Leases

Adding SMB3 **directory-lease** support to [hierynomus/smbj](https://github.com/hierynomus/smbj)
(the SMB client Cyberduck/Mountain Duck use) so directory listings can be cached
client-side and trusted until the server pushes a lease break — the feature Samba
shipped in 4.22 (`smb3 directory leases`).

## Layout
```
smbj/        cloned smbj (working copy — we patch this)
reference/SMBClient/   Apple's open-source SMB client (read-only reference model)
docs/        research digests (read first)
  ms-smb2-lease-spec.md       wire formats [MS-SMB2] + Samba behavior
  apple-smbclient-leases.md   Apple's lease model (the reference design)
  smbj-analysis.md            exact smbj change points w/ file:line anchors
specs/       the implementation spec set (00-overview → 08-test-plan)
server/      the isolated Samba 4.23.8 test server (Docker, deploy to .12)
```

## Test server (running)
Samba **4.23.8** in Docker on **<smb-host>:1445**, `smb3 directory leases = Yes`,
share **testshare** (creds `smbj` / `changeit`), isolated from .12's system smbd
(4.19.5 on :445). Redeploy / teardown:
```bash
ssh <smb-host> 'cd /home/smbj/smbj-dirlease/server && bash deploy.sh'
ssh <smb-host> 'docker rm -f smbj-dirlease'   # teardown
```

## Build & test (this Mac)
```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@17        # installed via brew
cd smbj
./gradlew --no-daemon clean test                     # unit suite — baseline 273 green
SMBJ_IT_HOST=<smb-host> ./gradlew --no-daemon \
  integrationTest --tests "*LiveSambaSmokeIntegrationTest"   # live harness vs .12
```
Test-naming gotcha: the Gradle suites only run classes ending in `Test`/`Spec`
(see `specs/08-tdd-test-plan.md`).

## Status (2026-06-07) — FEATURE COMPLETE, all milestones live-verified
| Item | State |
|------|-------|
| Test server (dir leases on) | ✅ up on .12:1445 (Samba 4.23.8) |
| Repos cloned + studied | ✅ smbj + Apple SMBClient |
| Research digests | ✅ `docs/` |
| Spec set 00–08 | ✅ `specs/` |
| TDD baseline | ✅ green (was 273; now **332** unit tests) |
| Live smoke harness (Mac→.12) | ✅ green |
| **M4** advertise leasing caps | ✅ live (`SmbConfig.withDirectoryLeasingEnabled`) |
| **M1** create-context layer | ✅ `SMB2CreateContext` (byte-exact) |
| **M2** lease model (RqLs V1/V2) | ✅ `LeaseKey`/`SMB2LeaseState`/`SMB2OplockLevel`/`SMB2LeaseCreateContext` |
| **M3** create req/resp wiring | ✅ byte-exact; **SigningBuffer fix** (see specs/03) |
| **M5** open-with-lease + LeaseManager | ✅ **live**: RH granted, ParentLeaseKey threaded |
| **M6** lease-break handling + ack | ✅ **live**: break received, acked, connection survives |
| **M7** directory cache | ✅ **live**: repeat list() 0 re-queries; break → re-query (no stale) |

Two empirical findings that cost real debugging time (both recorded in the specs):
1. A client **must advertise** `LEASING`+`DIRECTORY_LEASING` in NEGOTIATE or Samba won't
   advertise/grant directory leasing (`specs/04`).
2. The CREATE request serializes against a **`SigningBuffer`** whose `wpos()` is always 0;
   offset/length math must use constants, not `wpos()` (`specs/03`).

### What it does, end to end
`DiskShare.openDirectory`/`list()` transparently request an SMB3 directory lease when the
server supports it; a repeated `list()` of an unchanged directory is served from an in-memory
cache with **zero** `QUERY_DIRECTORY` round-trips; when the server pushes a lease break
(because someone changed the directory) the client receives it, acknowledges it, and evicts
the cache so the next `list()` re-queries and reflects the change. Falls back to today's exact
behaviour against a lease-unaware server (the bundled Testcontainers image; see `specs/08` to
bump it for CI).

### Run the live suite
```
SMBJ_IT_HOST=<smb-host> ./gradlew --no-daemon integrationTest \
  --tests "*DirectoryLease*IntegrationTest" --tests "*LiveSambaSmoke*"
```

Implementation order and the failing-first test for each milestone are in
`specs/00-overview.md` (§milestone plan) and `specs/08-tdd-test-plan.md`. Next: a perf
benchmark (lease-on / lease-off / old-server) over a deep tree, and upstreaming to smbj.
