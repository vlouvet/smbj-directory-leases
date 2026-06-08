# Using this smbj (with SMB3 directory leases) in Cyberduck / `duck`

Cyberduck and its CLI `duck` use **smbj** as their SMB engine, bundled as a JAR. They
have no setting to point at a different SMB library, so to run this fork's
directory-lease build you **swap our `smbj` JAR in for the bundled one**. Our changes are
**transparent** to Cyberduck's code — `openDirectory`/`list()` request a lease and serve
repeat listings from cache automatically — so **no Cyberduck source change is needed**.

> This is for **local testing**. The durable path is to get directory leases into an
> upstream smbj release; Cyberduck then picks it up via a normal dependency bump. See
> [Upstreaming](#upstreaming).

---

## 0. Prerequisites
- JDK 17 (to run Gradle 8.2; the jar itself targets Java 8).
- A **Samba ≥ 4.22** share with `smb3 directory leases = yes` (or Windows) to actually
  exercise leases. See [`server/`](server/) for a ready Dockerised Samba 4.23 server.
- macOS for the steps below (the JAR-swap idea is the same on Windows/Linux; only the
  app-bundle/signing details differ).

## 1. Build the smbj JAR
```bash
cd smbj            # the repo root (this fork)
export JAVA_HOME=/path/to/jdk17
./gradlew jar
ls build/libs/     # -> smbj-<version>.jar  (e.g. smbj-0.1.0-SNAPSHOT.jar)
```

## 2. Check version compatibility (once)
Cyberduck bundles a specific smbj (e.g. `smbj-0.14.0.jar`). Our jar must be a **binary
superset** of that — i.e. contain every class/method Cyberduck's `smb-*.jar` calls.
Confirm no classes are missing:
```bash
APP=/Applications/Cyberduck.app
BUNDLED=$(ls "$APP"/Contents/Resources/smbj-*.jar)
unzip -l "$BUNDLED"               | awk '{print $4}' | grep '\.class$' | sort > /tmp/bundled.txt
unzip -l build/libs/smbj-*.jar    | awk '{print $4}' | grep '\.class$' | sort > /tmp/ours.txt
comm -23 /tmp/bundled.txt /tmp/ours.txt    # MUST be empty (nothing the bundle has that we lack)
```
This fork is based on smbj master and is a superset of 0.14.0. If Cyberduck bundles a
*newer* smbj than this fork's base, rebase the changes before swapping.

## 3a. Cyberduck.app (GUI)
Work on a **copy** so your real install is untouched. Cyberduck is signed + notarized with
a hardened runtime, so the modified bundle must be re-signed ad-hoc to launch.

```bash
SRC=/Applications/Cyberduck.app
DST=/Applications/Cyberduck-smbj.app
cp -R "$SRC" "$DST"

# Swap the jar, keeping the EXACT filename (the launcher lists it on the classpath).
BUNDLED_NAME=$(basename "$DST"/Contents/Resources/smbj-*.jar)
cp build/libs/smbj-*.jar "$DST/Contents/Resources/$BUNDLED_NAME"

# (Recommended) give the copy a distinct identity so it can't clobber your real
# Cyberduck's prefs/keychain or get confused in LaunchServices:
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier ch.sudo.cyberduck.dirlease" "$DST/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleName Cyberduck-smbj" "$DST/Contents/Info.plist"

# Re-sign ad-hoc (drops hardened runtime so the modified bundle loads) and de-quarantine.
codesign --remove-signature "$DST" 2>/dev/null || true
codesign --force --deep --sign - "$DST"
xattr -dr com.apple.quarantine "$DST"
```

**Launch it:** ad-hoc-signed apps are rejected by Gatekeeper via a normal double-click, so
the first time **right-click `Cyberduck-smbj.app` → Open → Open** (one-time approval).
Thereafter it launches normally.

**Verify the swapped jar is actually loaded** (after it's running):
```bash
PID=$(pgrep -f "Cyberduck-smbj.app/Contents/MacOS")
lsof -p "$PID" | grep -i "Resources/smbj-.*\.jar"     # shows our jar open in the JVM
```

> **Do NOT let it auto-update.** Installing an update replaces the bundle and **wipes the
> jar swap**. Dismiss update prompts ("Skip This Version"); optionally disable Sparkle on
> the *copy* only.

## 3b. `duck` CLI (headless — easiest to script)
`duck` is a plain JVM tool (no app bundle / Gatekeeper), so there's no re-sign step.
```bash
brew install duck
JAR=$(find "$(brew --prefix)/Cellar/duck" -name 'smbj-*.jar' | head -1)
cp "$JAR" "$JAR.orig"                       # back up
cp build/libs/smbj-*.jar "$JAR"             # swap (keep the same filename)

duck --username <user> --password <password> --list "smb://<smb-host>:<port>/<share>/"
```
(Use a single recursive/`--synchronize` operation to exercise the *cache* — see Caveats.)

## 4. No configuration needed
Directory leasing is **on by default** in this fork: `SmbConfig.directoryLeasingEnabled`
defaults to `true` at the field level, so it's active for configs built via
`SmbConfig.builder()` — which is how Cyberduck builds its config. The client only actually
*requests* a lease when the negotiated server advertises `DIRECTORY_LEASING` (SMB 3.x), so
older/non-supporting servers transparently fall back to today's behaviour.

## 5. Confirm leases are really being granted (server-side proof)
Stock smbj never requests directory leases, so their presence proves this fork is active.
While Cyberduck/`duck` is browsing the share, on the **server**:
```bash
smbstatus --leases        # (Samba) -> shows directory leases (e.g. state RH) for open dirs
# or inside the Docker test server:
docker exec <container> smbstatus --leases
```
A directory lease in that output = our code is live in Cyberduck.

---

## Caveats & gotchas (learned the hard way)
- **Per-connection cache.** The listing cache lives on the SMB connection. A repeated
  `list()` of an unchanged directory is served from memory **within one connection** (or a
  single recursive walk). Separate one-shot `duck --list` invocations each open a fresh
  connection, so they won't show the warm-cache speedup — use one recursive/sync op.
- **App open/close pattern.** Cyberduck opens a directory, **closes** its handle, then
  lists. The cache therefore keeps its **own** dedicated directory handle (never the app's
  closed one); otherwise you'd get `STATUS_FILE_CLOSED`. That fix is in this fork.
- **Search is a Cyberduck UI feature.** Cyberduck's recursive search (`SearchWorker`) lists
  every directory and filters client-side; "results show the folder" / live-filter behaviour
  is in Cyberduck above smbj. The SMB listing itself is complete (verified over a
  1,365-directory tree).
- **Version drift.** Re-run the §2 class-diff whenever Cyberduck/`duck` updates its bundled
  smbj; rebase if their base moved past this fork's.

## Upstreaming
The JAR swap is a testing shim. The right long-term path:
1. Land directory-lease support in **hierynomus/smbj** (this fork is the basis for a PR).
2. Cyberduck bumps its smbj dependency in a future release — then it "just works" with no
   swap, no re-sign, and survives updates.
