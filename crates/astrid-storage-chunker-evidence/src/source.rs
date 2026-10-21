use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SourceRecord {
    pub component: &'static str,
    pub version: &'static str,
    pub source_revision: &'static str,
    pub repository: &'static str,
    pub license: &'static str,
    pub role: &'static str,
}

#[derive(Debug, Serialize)]
pub struct UnavailableCandidate {
    pub name: &'static str,
    pub inspected_revision: &'static str,
    pub repository: &'static str,
    pub status: &'static str,
    pub reasons: [&'static str; 4],
}

pub fn source_records() -> [SourceRecord; 4] {
    [
        SourceRecord {
            component: "fastcdc",
            version: "5.0.0",
            source_revision: "eeb3cbe8ed4eeef020aa346707bbdb29abd814ad",
            repository: "https://github.com/nlfiedler/fastcdc-rs",
            license: "MIT",
            role: "production algorithm and evidence baseline for even profiles",
        },
        SourceRecord {
            component: "fastcdc-v4",
            version: "4.0.1",
            source_revision: "2e47aa3146c6dbae34896997eebd162b280a7052",
            repository: "https://github.com/nlfiedler/fastcdc-rs",
            license: "MIT",
            role: "legacy compatibility scan for odd revision-1 profiles",
        },
        SourceRecord {
            component: "mincdc",
            version: "0.1.0",
            source_revision: "638840e6809274e3e8e9916951d3c3ae4f3f5191",
            repository: "https://github.com/orlp/mincdc",
            license: "Zlib",
            role: "accelerated evidence oracle; never format authority",
        },
        SourceRecord {
            component: "mothcdc",
            version: "0.7.2",
            source_revision: "3900c1e4e6c311bf832cb5099b2e0170e070970f",
            repository: "https://github.com/russellromney/mothcdc",
            license: "Zlib",
            role: "adjacent-repeat representation evidence; never format authority",
        },
    ]
}

pub fn unavailable_candidates() -> [UnavailableCandidate; 1] {
    [UnavailableCandidate {
        name: "Chonkers",
        inspected_revision: "4fff91bae8eceaf209850544a00ecaa67e5ffb6b",
        repository: "https://github.com/ichteltelch/chonkers",
        status: "not measured as a byte-exact Astrid candidate",
        reasons: [
            "the reference code is a hierarchical Java experiment over caller-supplied proto-chunks, not a canonical byte-stream profile",
            "the repository has no license grant",
            "the repository has no independent reader, golden boundary fixtures, or conformance tests",
            "inventing byte preprocessing or layer parameters would manufacture evidence rather than reproduce it",
        ],
    }]
}
