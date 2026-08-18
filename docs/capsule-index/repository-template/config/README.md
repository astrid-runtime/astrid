# Public configuration and trust material

Copy `index.toml.example` to `index.toml` and replace its placeholders.  Add
the public, signed TUF root as `trust-root.json` after the offline ceremony.
Never add a root private key, timestamp key, snapshot key, targets key, signing
seed, or secret to this directory.  The `.gitignore` below is defense in depth;
the PR validator also scans file names and contents and fails closed.
