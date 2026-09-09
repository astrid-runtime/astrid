Leave unset optional distro credentials absent during initialization instead of
attempting to store invalid empty secrets. Reinitialization preserves existing
credentials; nonempty secrets still use the daemon's typed secret API.
