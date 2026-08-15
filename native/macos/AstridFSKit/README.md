# Astrid FSKit provider

This macOS app hosts the native `astridfs` FSKit extension. It is a filesystem
adapter, not a storage authority: the extension receives a private path
resource containing a kernel-issued lease and callback socket, and every file
operation is performed against the owner already fixed in that lease.

The path-backed FSKit resource API used here is available on macOS 26 or newer.
Astrid's provider-neutral kernel API is also used by Linux FUSE and Windows
WinFsp adapters; those adapters do not share this Xcode target.

The app and extension require a valid Apple signature and the
`com.apple.developer.fskit.fsmodule` entitlement. Set a development team in the
project (or supply it on the `xcodebuild` command line), install `AstridFS.app`
under `/Applications`, and enable the extension in System Settings. The
co-installed `astrid-storage-provider-fskit` Rust companion handles mount,
status, sync, and unmount lifecycle requests from the CLI.

For a syntax-only check that does not require signing:

```sh
scripts/check-macos-fskit.sh
```

For a signed development or release build, authenticate Xcode with the Apple
team that owns the bundle identifiers, then run:

```sh
ASTRID_FSKIT_DEVELOPMENT_TEAM=<team-id> scripts/build-macos-fskit.sh
```

The script refuses to emit an unsigned app and verifies the resulting bundle's
embedded app extension signature. Distribution notarization remains part of
the release-signing environment rather than source validation.

Once installed, a principal can mount its own view with:

```sh
astrid storage mount --as default ~/Astrid/default
```

Mounting does not provision storage. It creates an authenticated OS view of
the existing Astrid store. `--fleet <uid>` selects the caller's shared fleet
owner; `--admin` selects system-owned storage and defaults to read-only.
