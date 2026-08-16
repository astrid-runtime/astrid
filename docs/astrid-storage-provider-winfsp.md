# Astrid WinFsp provider

`astrid-storage-provider-winfsp` implements the Windows native adapter for Astrid's
provider-neutral version-two filesystem callback protocol, including base64
framing for the full 4 MiB I/O bound. The lifecycle provider obtains a
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
An existing WinFsp 1.x installation is left untouched because the upstream 2.x
MSI cannot upgrade it in place; the installer reports the required deliberate
operator action instead of removing a shared filesystem dependency.

There are no legacy Windows migration obligations. Windows ARM64 is cross-checked
for compilation; native runtime verification is x86_64-only.
