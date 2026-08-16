# Astrid WinFsp provider

`astrid-storage-provider-winfsp` implements the Windows native adapter for Astrid's
provider-neutral filesystem callback protocol. The lifecycle provider obtains a
kernel-issued lease, starts a detached WinFsp host process, and translates WinFsp
operations to the bounded callback contract. The callback endpoint is a
path-scoped named pipe with a fixed current-user/LocalSystem DACL and requires the
random lease token.

The Windows x86_64 release archive includes the provider, its co-installed
`winfsp-x64.dll`, and the digest-pinned WinFsp 2.1.25156 MSI. The MSI installs
the shared WinFsp driver; Astrid does not install or provision a kernel driver by
itself. `install-windows.ps1` installs the pinned dependency when needed and
copies the release files. `uninstall-windows.ps1` removes only those files and
can remove WinFsp explicitly with `-RemoveWinFsp` when Astrid installed it.

There are no legacy Windows migration obligations. Windows ARM64 is cross-checked
for compilation; native runtime verification is x86_64-only.
