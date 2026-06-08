# 08 — TDD Test Plan & Harness

How every change in specs 01–07 is proven, in order, failing-first → green. This is
the spec that keeps the project honest: no milestone is "done" until its tests are green
and the full suite stays green.

## Test taxonomy
| Layer | Where | Framework | Network | Speed |
|-------|-------|-----------|---------|-------|
| **Unit** | `src/test/groovy`, `src/test/java` | Spock + JUnit-Jupiter + Mockito/AssertJ | none | ms |
| **Integration (portable)** | `src/it/java`, `src/it/groovy` | JUnit + **Testcontainers** | local Docker | seconds |
| **Integration (live)** | `src/it/java/.../smoke` | JUnit | external **.12:1445** | seconds |

Unit tests are byte-exact and offline — they are the primary TDD driver for the
serializers (specs 01–03, 06). Integration tests prove real interop (specs 04–07).

## CRITICAL harness gotchas (learned the hard way)
1. **Test naming filter.** `build.gradle`'s `configureEach` applies
   `include "**/*Test.*"` + `include "**/*Spec.*"` to *every* suite (unit AND
   integrationTest). A class that doesn't end in `Test` or `Spec` is silently **not run**
   ("No tests found"). Name integration tests `*IntegrationTest` (repo convention:
   `SMB2DirectoryIntegrationTest`, etc.). Name unit specs `*Spec`.
2. **Java 8 target.** `options.release = 8` — no Java 9+ API in `src/main` (e.g. no
   `List.of`, no `var`). Tests may use newer APIs (compiled/run under JDK 17).
3. **Run with JDK 17:** `export JAVA_HOME=/opt/homebrew/opt/openjdk@17` (Gradle 8.2 wrapper).
4. **`integrationTest` is not part of `build`** (`shouldRunAfter(test)`); run it explicitly.

## Commands
```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@17
cd smbj
./gradlew --no-daemon clean test                                   # all unit tests (baseline: 273 green)
./gradlew --no-daemon test --tests "*SMB2CreateContextSpec"         # a single unit spec
# live IT against the .12 server (defaults baked into the test; override via env):
SMBJ_IT_HOST=<smb-host> ./gradlew --no-daemon integrationTest --tests "*LiveSambaSmokeIntegrationTest"
SMBJ_IT_HOST=<smb-host> ./gradlew --no-daemon integrationTest --tests "*Lease*IntegrationTest"
# portable IT (Testcontainers, needs local Docker):
./gradlew --no-daemon integrationTest --tests "*DirectoryLease*IntegrationTest"
```

## Live server harness (already running)
- Samba **4.23.8** in Docker on **<smb-host>:1445**, `smb3 directory leases = Yes`.
- Share **testshare** → `/home/smbj/smbj-dirlease/testshare`; creds **smbj / changeit**.
- Seeded with `readme.txt` + `subdir/`. Config + redeploy in `server/` (this repo).
- **Forcing a lease break** (for specs 06/07 tests) — mutate the dir out-of-band so the
  server breaks the client's RH lease. Options, cheapest first:
  - a **second smbj connection** that creates/deletes a file in the leased dir;
  - on the server: `ssh <smb-host> 'docker exec smbj-dirlease sh -c "touch /share/break-$$"'`
    or a second `smbclient` session.
  The test must **wait on a latch/poll** for the break (never `sleep`).

## Portable image bump (REQUIRED before specs 05–07 integration tests can run in CI)
The bundled Testcontainers image is lease-unaware:
`src/it/java/com/hierynomus/smbj/testcontainers/SambaContainer.java:59` builds from
**`alpine:3.18.3`** → Samba ~4.18 (**no directory leases**), and
`src/it/docker-image/smb.conf` sets **no** lease/oplock directives.

Change set (mirror this repo's `server/`):
1. `SambaContainer.Builder.accept(...)` — bump base to a Samba ≥4.22 source. Either
   `alpine:edge` **with `apk upgrade` first** (the musl/`renameat2` fix we hit — see
   `server/Dockerfile`), or pin a known-good tag. Verify `smbd --version` ≥ 4.22 at build.
2. `src/it/docker-image/smb.conf` — add to `[global]`:
   ```
   server min protocol = SMB2_10
   server max protocol = SMB3_11
   smb3 directory leases = yes
   oplocks = yes
   level2 oplocks = yes
   kernel oplocks = no
   ```
   and a writable lease share (the existing `user` share works if writable).
3. Keep the existing shares so current ITs stay green.
Until this lands, specs 05–07 integration tests run **only** against live `.12`
(gate them with `@EnabledIfEnvironmentVariable(named="SMBJ_IT_HOST", matches=".+")` so CI
skips rather than fails). The smoke test should get the same guard before upstreaming.

## Milestone → test matrix (failing-first each step)
| Spec | Unit (offline, primary) | Integration (interop) |
|------|-------------------------|------------------------|
| 01 create-contexts | `SMB2CreateContextSpec` — chained/padded/empty round-trips (byte-exact) | — |
| 02 lease-model | `LeaseKeySpec`, `SMB2LeaseStateSpec`, `SMB2LeaseCreateContextSpec` (V2 52B bytes), `SMB2LeaseResponseContextSpec` (V1/V2 by DataLength) | — |
| 03 create-wiring | `SMB2CreateRequestSpec` (context emitted, oplock=0xFF), `SMB2CreateResponseSpec` (lease parsed); **no-context regression byte-identical** | — |
| 04 negotiate-caps | `SmbConfigTest` (caps incl/excl), `ConnectionContextSpec` (0x20 with/without; dialect gate) | `LiveSambaSmokeIntegrationTest` (server advertises 0x20) ✅ already added |
| 05 open-with-lease | `LeaseManagerSpec` (register-before-send, parent-key threading) | `DirectoryLeaseOpenIntegrationTest`: open root → OplockLevel=LEASE, granted RH; open subdir → ParentLeaseKey==root key + PARENT_LEASE_KEY_SET |
| 06 lease-break | `SMB2LeaseBreakNotificationSpec` (parse 44B), `SMB2LeaseBreakAcknowledgmentSpec` (build 36B), epoch-stale ignored | `DirectoryLeaseBreakIntegrationTest`: hold RH, mutate from 2nd conn → break received + acked, state drops |
| 07 directory-cache | `LeasedDirectoryCacheSpec` (populate/serve/evict, snapshot immutable) | `DirectoryLeaseCacheIntegrationTest`: 2nd `list()` = 0 extra QUERY_DIRECTORY (counter); post-break `list()` re-queries + reflects change (no stale read) |

## Regression guardrails
- The **273-test** unit baseline must stay green after every milestone (`./gradlew clean test`).
- Every existing integration test must still pass against the bumped image.
- The "no-context CREATE is byte-identical to today" assertion (spec 03) is the canary that
  the new optional path never perturbs the default path.

## Definition of done (whole feature)
1. All unit specs above green; baseline never regressed.
2. Live IT suite green against `.12`: lease granted (RH) on dir open, ParentLeaseKey threaded,
   break received+acked, cache served then invalidated (no stale read).
3. Portable IT suite green against the bumped Testcontainers image.
4. `./gradlew clean build` green end to end.
