# Astrid FSKit provider

This hidden macOS app hosts the native `astridfs` FSKit extension. It is a filesystem
adapter, not a storage authority: the extension receives a private path
resource containing a kernel-issued lease and callback socket, and every file
operation is performed against the owner already fixed in that lease.

The containing app is an `LSUIElement` background process with no scenes,
windows, Dock icon, or menu-bar item. It exists only because macOS requires an
app container for the extension. `astrid storage mount`, `status`, `sync`, and
`unmount` are the sole storage lifecycle interface.

The path-backed FSKit resource API used here is available on macOS 26 or newer.
Astrid's provider-neutral kernel API is also used by Linux FUSE and Windows
WinFsp adapters; those adapters do not share this Xcode target.

The app and extension require a valid Apple signature and the
`com.apple.developer.fskit.fsmodule` entitlement. Set a development team in the
project (or supply it on the `xcodebuild` command line), install `AstridFS.app`
under `/Applications`, and enable the extension in System Settings. The
co-installed `astrid-storage-provider-fskit` Rust companion handles mount,
status, sync, and unmount lifecycle requests from the CLI. Installation selects
only the companion staged beside the app and requires its Developer ID
signature and Astrid version to match.

The source-tree check is a syntax/typecheck and unsigned Xcode contract check.
It also rejects an ordinary window or menu-bar scene and requires the generated
app plist to declare `LSUIElement`;
it does not claim that `astridfs` can be mounted:

```sh
scripts/check-macos-fskit.sh
```

For a signed development or release build, authenticate Xcode with the Apple
team that owns the bundle identifiers, then run:

```sh
ASTRID_FSKIT_DEVELOPMENT_TEAM=<team-id> scripts/build-macos-fskit.sh
```

The script refuses to emit an unsigned app, verifies both signatures, and checks
the extension's FSKit entitlement. Release builds set
`ASTRID_FSKIT_NOTARIZE=1` with real App Store Connect API credentials; the
script calls `notarytool`, staples the ticket, and validates the staple. Missing
credentials are a build failure, never a fake-signing path.

The macOS release archive includes the signed, notarized app, extension, Rust
companion, validator, and lifecycle manager. After extracting the archive:

```sh
macos/manage-macos-fskit.sh install
macos/manage-macos-fskit.sh enable
macos/manage-macos-fskit.sh status
```

`enable` and `status` fail unless `pluginkit` reports the exact installed
extension identifier, app path, and displayed installed version as elected.
When election is unavailable they name the exact System Settings pane instead
of treating plugin discovery or a running containing process as proof. Process
validation binds the executable path, PID, codesign identity, signing team, and
installed Astrid version.

To replace it with a newly downloaded and extracted release, run `update`. To
remove it, first unmount every Astrid filesystem and run `uninstall`; the app is
moved to the Finder Trash. A release-gated ignored Rust test performs an actual
FSKit mount/unmount round trip when supplied a live lease; ordinary CI stops at
typecheck and artifact validation.

Once installed, a principal can mount its own view with:

```sh
astrid storage mount --as default ~/Astrid/default
```

Mounting does not provision storage. It creates an authenticated OS view of
the existing Astrid store. `--fleet <uid>` selects the caller's shared fleet
owner; `--admin` selects system-owned storage and defaults to read-only.
