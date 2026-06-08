# SMB3 Directory Leases for smbj

This fork of [hierynomus/smbj](https://github.com/hierynomus/smbj) adds **SMB3 directory-lease**
support — letting a client cache directory listings and trust them until the server pushes a
lease break. It's the same mechanism Windows and Apple's SMB client use, and the feature
Samba added in 4.22 (`smb3 directory leases`). The payoff: repeated `list()` of an unchanged
directory is served from memory with **zero** `QUERY_DIRECTORY` round-trips.

## What was added
- **Create-context layer** — `SMB2CreateContext` (de)serialization (`mssmb2.messages.create`).
- **Lease model** — `LeaseKey`, `SMB2LeaseState`/`Flags`, `SMB2OplockLevel`, and the `RqLs`
  V1/V2 create-context request writer + response parser.
- **CREATE wiring** — `SMB2CreateRequest`/`Response` carry contexts + the oplock/lease level
  (backward compatible; the no-context path is byte-identical).
- **Negotiate** — `SmbConfig` advertises `LEASING`/`DIRECTORY_LEASING` (default on).
- **Open-with-lease** — `DiskShare.openDirectory`/`list()` request a V2 RH directory lease;
  `LeaseManager`/`LeaseEntry` track leases per connection, with ParentLeaseKey threading.
- **Lease-break handling** — server-pushed `OPLOCK_BREAK` (the all-FF form) is routed off the
  read thread, parsed, epoch-checked, acknowledged, and used to invalidate the cache.
- **Directory cache** — `LeasedDirectoryCache` serves repeat listings from memory and evicts on
  break, via a dedicated kept-open handle the application never closes.

## Status
- **332 unit tests** + a live integration suite (open/lease, break+ack, cache serve/invalidate)
  pass against a Samba 4.23 directory-lease server.
- Verified end-to-end through Cyberduck (jar swap) — including a recursive search over a
  1,365-directory tree.

## Design docs, specs, test harness, and benchmark
See [`directory-lease-project/`](directory-lease-project/):
- `specs/00..08` — the implementation spec set (one per milestone, byte-precise, TDD-first).
- `docs/` — research digests: [MS-SMB2] lease wire format, Apple's reference model, and an
  smbj change-point analysis.
- `server/` — a reproducible Dockerised Samba 4.23 test server + a benchmark harness.
- `BENCHMARK.md` — measured results: repeat listing/search on a deep tree drops from ~hundreds
  of ms to ~1–2 ms (requests eliminated, not just wall-clock).

## Running the live tests
```bash
export JAVA_HOME=/path/to/jdk17
SMBJ_IT_HOST=<smb-host> SMBJ_IT_PORT=1445 SMBJ_IT_USER=<user> SMBJ_IT_PASS=<password> \
  ./gradlew integrationTest --tests "*DirectoryLease*IntegrationTest"
```
Unit tests: `./gradlew test`. See `directory-lease-project/README.md` for the full harness.
