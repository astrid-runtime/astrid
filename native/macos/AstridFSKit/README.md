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

For a signed release build, install the Developer ID provisioning profiles for
both bundle identifiers, then select them separately by name or UUID:

```sh
ASTRID_FSKIT_DEVELOPMENT_TEAM=<team-id> \
ASTRID_FSKIT_APP_PROFILE='<app-profile-name-or-uuid>' \
ASTRID_FSKIT_EXTENSION_PROFILE='<extension-profile-name-or-uuid>' \
  scripts/build-macos-fskit.sh
```

The script refuses to emit an unsigned app, verifies both signatures, and checks
the extension's FSKit entitlement. Release builds set
`ASTRID_FSKIT_NOTARIZE=1` with real App Store Connect API credentials or an
explicit notarization keychain profile and keychain path; the
script calls `notarytool`, staples the ticket, and validates the staple. Missing
credentials are a build failure, never a fake-signing path.

The release workflow reads base64-encoded provisioning profiles from repository
secrets `ASTRID_MACOS_APP_PROVISIONING_PROFILE` and
`ASTRID_MACOS_EXTENSION_PROVISIONING_PROFILE`. Its wrapper validates the team,
bundle identifiers, expiration, distribution scope, and extension FSKit feature,
installs UUID-named profiles for the signing command, and removes only files it
created. Existing profiles are never overwritten. The profiles must authorize
the Developer ID certificate supplied separately to CI; a P12 export does not
include provisioning profiles. Release signing disables Xcode's automatic base
entitlement injection and refuses a signed app that enables `get-task-allow`.

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
