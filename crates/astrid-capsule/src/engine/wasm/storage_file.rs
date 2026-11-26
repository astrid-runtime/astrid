//! Buffered file state for a handle in the storage-backed VFS.

use vstd::prelude::*;

verus! {

pub(super) struct OpenFile<P> {
    path: P,
    pub(super) bytes: Vec<u8>,
    pub(super) offset: usize,
    writable: bool,
    pub(super) dirty: bool,
}

pub(super) enum WriteRange {
    ReadOnly,
    Overflow,
    End(usize),
}

impl<P> OpenFile<P> {
    pub(super) closed spec fn destination(&self) -> P { self.path }
    pub(super) closed spec fn buffered(&self) -> Seq<u8> { self.bytes@ }
    pub(super) closed spec fn position(&self) -> usize { self.offset }
    pub(super) closed spec fn can_write(&self) -> bool { self.writable }
    pub(super) closed spec fn changed(&self) -> bool { self.dirty }

    pub(super) fn new(path: P, bytes: Vec<u8>, writable: bool, dirty: bool) -> (file: Self)
        ensures file.destination() == path, file.buffered() == bytes@, file.position() == 0,
            file.can_write() == writable, file.changed() == dirty,
    {
        Self { path, bytes, offset: 0, writable, dirty }
    }

    pub(super) fn write_range(&self, length: usize) -> (range: WriteRange)
        ensures match range {
            WriteRange::ReadOnly => !self.can_write(),
            WriteRange::Overflow => self.can_write() && self.position() + length > usize::MAX,
            WriteRange::End(end) => self.can_write() && end == self.position() + length,
        },
    {
        if !self.writable { return WriteRange::ReadOnly; }
        match self.offset.checked_add(length) {
            Some(end) => WriteRange::End(end),
            None => WriteRange::Overflow,
        }
    }

    /// Capture the original destination and the complete buffered bytes for publication.
    pub(super) fn publication(&self) -> (target: Option<(&P, &Vec<u8>)>)
        ensures target.is_some() == (self.can_write() && self.changed()),
            match target {
                Some((path, bytes)) => *path == self.destination() && bytes@ == self.buffered(),
                None => true,
            },
    {
        if self.writable && self.dirty { Some((&self.path, &self.bytes)) } else { None }
    }
}

}
