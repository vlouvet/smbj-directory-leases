# smbj Directory Leases — Implementation Spec (Overview)

Goal: add **SMB3 directory-lease** support to [hierynomus/smbj](https://github.com/hierynomus/smbj)
so a client can cache directory enumerations and trust them until the server
pushes a lease break — the same mechanism Apple's smbfs and Windows use, and the
feature Samba added in 4.22 (`smb3 directory leases`).

This is the connective-tissue doc. Detailed, per-area specs live alongside it
(`01-…` … `08-…`) and are written to be implemented **in order**, each landing a
green test before the next begins (TDD).

## Source material (read these first)
- `docs/ms-smb2-lease-spec.md` — wire formats ([MS-SMB2]) + Samba 4.22 behavior.
- `docs/apple-smbclient-leases.md` — Apple's reference model (lease key per-node,
  ParentLeaseKey threading, register-before-send, break→invalidate→close = implicit ack).
- `docs/smbj-analysis.md` — exact smbj change points with `file:line` anchors.

## Current state of smbj (confirmed)
smbj has **scaffolding but no functional lease path**:
- Capability enums exist: `SMB2GlobalCapability.SMB2_GLOBAL_CAP_LEASING (0x02)`,
  `…_DIRECTORY_LEASING (0x20)` (`mssmb2/SMB2GlobalCapability.java:25,29`).
- Negotiate gating helpers exist: `ConnectionContext.supportsFileLeasing()` /
  `supportsDirectoryLeasing()` (`smbj/connection/ConnectionContext.java:181,199`).
- Break detection exists: `SMB2PacketData.isOplockBreakNotification()`
  (`mssmb2/SMB2PacketData.java:65`); `SMB2_OPLOCK_BREAK(0x12)` is a known command.

…but:
- `SMB2CreateRequest` hardcodes `RequestedOplockLevel = 0` (`…/messages/SMB2CreateRequest.java:65`)
  and `CreateContextsOffset/Length = 0` (`:93-94`) — **no create context is ever sent**.
- `SMB2CreateResponse` discards `OplockLevel` (`:48`) and ignores response contexts (`:61-63`).
- `SmbConfig` never advertises LEASING/DIRECTORY_LEASING in client capabilities
  (`src/main/java/com/hierynomus/smbj/SmbConfig.java`).
- The handler chain (`Connection.java:121-128`) has **no route** for a server-pushed
  break; an unsolicited break currently NPEs/throws downstream.
- There is **no create-context abstraction, no lease model, no ack, no cache.**

So this is a green-field build on top of real scaffolding.

## Test harness (already stood up)
- **Live server:** Samba **4.23.8** in Docker on **<smb-host>:1445**
  (`smb3 directory leases = Yes`), share `testshare` → `/home/smbj/smbj-dirlease/testshare`,
  creds `smbj` / `changeit`. Isolated from the host's system smbd (4.19.5 on 445).
  Config under `server/` in this repo; redeploy with `server/deploy.sh`.
- **Self-contained server:** smbj's own `integrationTest` suite uses Testcontainers
  (`src/it/java/com/hierynomus/smbj/testcontainers/SambaContainer.java`,
  `src/it/docker-image/`). Its bundled Samba image is currently lease-unaware and must
  be bumped to a ≥4.22 image with `smb3 directory leases = yes` for CI-portable tests
  (see `08-tdd-test-plan.md`).
- **Toolchain:** Gradle 8.2 (wrapper), compiles to Java 8 (`build.gradle:43 options.release = 8`),
  run with JDK 17 (`/opt/homebrew/opt/openjdk@17`). Tests: Spock/Groovy + JUnit-Jupiter.

## Naming & package conventions (CANONICAL — all specs/impl follow these)
New code mirrors existing smbj patterns (see `messages/negotiate/SMB2NegotiateContext.java`
as the template for context (de)serialization).

Create-context model — new package `com.hierynomus.mssmb2.messages.create`:
- `SMB2CreateContext` — value holder: `name` (byte[]/4CC), `data` (byte[]); static
  `writeAll(SMBBuffer, List<SMB2CreateContext>)` handling 8-byte alignment + `Next` chaining,
  and `readAll(SMBBuffer, offset, length)`.
- Lease payloads encode/decode into/out of `SMB2CreateContext.data`:
  - `SMB2LeaseCreateContext` (request) — writes `RqLs`; supports V1 (32B) and V2 (52B).
  - `SMB2LeaseResponseContext` (response) — parses V1/V2, **disambiguated by DataLength (32 vs 52)**.

Lease primitives — package `com.hierynomus.mssmb2`:
- `LeaseKey` — 16-byte identity (UUID-derived), value object with equals/hashCode.
- `SMB2LeaseState` — `EnumWithValue`: `SMB2_LEASE_NONE(0x0)`, `READ_CACHING(0x1)`,
  `HANDLE_CACHING(0x2)`, `WRITE_CACHING(0x4)`. Helpers for set membership (R, RH).
- `SMB2LeaseFlags` — `SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET(0x04)`.
- `SMB2OplockLevel` — `EnumWithValue`: `NONE(0x00)`, `II(0x01)`, `EXCLUSIVE(0x08)`,
  `BATCH(0x09)`, `LEASE(0xFF)`. Replaces the magic bytes at `SMB2CreateRequest.java:65`.

Break handling — package `com.hierynomus.mssmb2.messages` + `com.hierynomus.smbj.connection`:
- `SMB2LeaseBreakNotification` (parse; StructureSize 44, command 0x12).
- `SMB2OplockBreakNotification` (parse; StructureSize 24) — for completeness/non-lease oplocks.
- `SMB2LeaseBreakAcknowledgment` / `SMB2LeaseBreakResponse` (StructureSize 36).
- `SMB2LeaseBreakPacketHandler` — new link in the chain that recognizes unsolicited
  breaks and dispatches them off the receive thread.
- `LeaseManager` (a.k.a. lease table) — registry keyed by `LeaseKey` → leased handle +
  cache; resolves a break to the right directory and drives invalidate/ack/close.

Directory cache — package `com.hierynomus.smbj.share`:
- `LeasedDirectoryCache` — per-leased-directory enumeration cache; populated from
  `QUERY_DIRECTORY`, served on repeat `list()`, invalidated on break.

## Milestone plan (each = one spec + green test before the next)
| # | Spec | Deliverable | Proves |
|---|------|-------------|--------|
| 1 | `01-create-contexts.md` | `SMB2CreateContext` read/write (alignment, chaining) | round-trip unit tests |
| 2 | `02-lease-model.md` | `LeaseKey`, `SMB2LeaseState/Flags`, `SMB2OplockLevel`, RqLs V1/V2 (de)serialize | byte-exact unit tests vs spec |
| 3 | `03-create-wiring.md` | wire contexts + oplock level into `SMB2CreateRequest`/`Response` | create-with-context round-trip; existing create tests still green |
| 4 | `04-negotiate-capabilities.md` | advertise LEASING/DIRECTORY_LEASING; gate on negotiated dialect/caps | negotiate unit test; live cap check vs .12 |
| 5 | `05-open-with-lease.md` | `DiskShare.openDirectory` requests a lease; `LeaseManager`; ParentLeaseKey threading; register-before-send | live IT vs .12: lease granted (RH) |
| 6 | `06-lease-break-handling.md` | inbound break routing, parse, epoch check, ack/close | live IT: external mutation → break received + acked |
| 7 | `07-directory-cache.md` | `LeasedDirectoryCache`: serve cached `list()`, invalidate on break | live IT: 2nd list served from cache; cache dropped on break |
| 8 | `08-tdd-test-plan.md` | full unit + IT matrix; bump bundled Samba image | green `build` + `integrationTest` |

## TDD strategy
- **Unit (fast, offline):** byte-level round-trip specs for every new (de)serializer,
  asserting exact wire bytes from `docs/ms-smb2-lease-spec.md`. Mirrors
  `src/test/groovy/com/hierynomus/mssmb2/messages/SMB2CreateResponseSpec.groovy`
  (`AbstractPacketReadSpec`, hex → `convert(bytes)`).
- **Integration (live, Docker):** end-to-end vs the .12 Samba (and, for CI, the bumped
  Testcontainers image). Each milestone 5-7 adds one IT that fails before and passes after.
- **Order:** write the failing test first, implement to green, refactor, move on.

## Non-goals (initial)
- Lease upgrade/downgrade optimization beyond what breaks require.
- File (non-directory) lease caching of *data* (we add file-lease plumbing only as far as
  it de-risks the break handler; directory caching is the payoff).
- Cyberduck/Mountain Duck integration (separate, downstream of an upstreamed smbj).
