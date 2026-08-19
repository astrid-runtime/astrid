#!/usr/bin/env bash

set -euo pipefail

python3 scripts/test_release_manifest.py
python3 scripts/test_musl_release_manifest.py
python3 scripts/test_windows_release_manifest.py
python3 scripts/test_validate_release_archive.py
python3 scripts/test_check_glibc.py
python3 scripts/test_check_dco.py
python3 scripts/test_check_static_elf.py
python3 scripts/test_release_publication.py
python3 scripts/test_release_draft_recovery.py
python3 scripts/test_crate_publication.py
python3 scripts/test_channel_metadata.py
python3 scripts/test_channel_publication.py
python3 scripts/test_nightly_version.py
bash scripts/test_channel_workflow_contract.sh
