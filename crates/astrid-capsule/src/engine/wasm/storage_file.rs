//! Buffered file state for a handle in the storage-backed VFS.

use vstd::prelude::*;

verus! {

pub(super) struct OpenFile<P> {
    path: P,
    bytes: Vec<u8>,
    offset: usize,
    writable: bool,
    dirty: bool,
}

pub(super) enum WriteRange {
    ReadOnly,
    Overflow,
    End(usize),
}

pub(super) enum OpenError<E> { Missing, TruncateDenied, Read(E) }

/// The classified storage path becomes the descriptor destination on every successful open.
pub(super) fn open_at<P,E,F:FnOnce(&P,u64,u64)->Result<Vec<u8>,E>>(
    path:P, existing:Option<u64>, write:bool, truncate:bool, read:F,
) -> (out:Result<OpenFile<P>,OpenError<E>>)
    requires existing matches Some(length) ==> read.requires((&path,0,length)),
    ensures
        out matches Ok(f) ==> f.destination() == path && f.position() == 0 && f.can_write() == write,
        if !write && existing.is_none() { out matches Err(OpenError::Missing) }
        else if !write && truncate { out matches Err(OpenError::TruncateDenied) }
        else if write && (truncate || existing.is_none()) {
            out matches Ok(f) && f.buffered().len() == 0 && f.changed()
        } else {
            match out {
                Ok(f) => !f.changed() && exists|b:Vec<u8>| b@ == f.buffered()
                    && #[trigger] read.ensures((&path,0,existing.unwrap()),Ok(b)),
                Err(OpenError::Read(e)) => read.ensures((&path,0,existing.unwrap()),Err(e)),
                _ => false,
            }
        },
{
    if !write && existing.is_none() { return Err(OpenError::Missing); }
    if !write && truncate { return Err(OpenError::TruncateDenied); }
    match existing {
        Some(length) if !truncate => match read(&path,0,length) {
            Ok(bytes) => Ok(OpenFile::new(path,bytes,write,false)),
            Err(error) => Err(OpenError::Read(error)),
        },
        _ => Ok(OpenFile::new(path,Vec::new(),write,true)),
    }
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

    fn write_range(&self, length: usize) -> (range: WriteRange)
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

    pub(super) fn read_remaining(&mut self) -> (bytes: Vec<u8>)
        requires old(self).position() <= old(self).buffered().len(),
        ensures
            bytes@ == old(self).buffered().subrange(
                old(self).position() as int, old(self).buffered().len() as int,
            ),
            final(self).buffered() == old(self).buffered(),
            final(self).position() == final(self).buffered().len(),
            final(self).destination() == old(self).destination(),
            final(self).can_write() == old(self).can_write(),
            final(self).changed() == old(self).changed(),
    {
        let (_, remaining) = self.bytes.as_slice().split_at(self.offset);
        let mut bytes = Vec::with_capacity(remaining.len());
        bytes.extend_from_slice(remaining);
        self.offset = self.bytes.len();
        bytes
    }

    pub(super) fn write_bytes(&mut self, content: &[u8]) -> (result: WriteRange)
        ensures
            match result {
                WriteRange::ReadOnly => !old(self).can_write() && *final(self) == *old(self),
                WriteRange::Overflow => old(self).can_write()
                    && old(self).position() + content.len() > usize::MAX
                    && *final(self) == *old(self),
                WriteRange::End(end) => {
                    &&& old(self).can_write()
                    &&& final(self).can_write() && final(self).changed()
                    &&& final(self).destination() == old(self).destination()
                    &&& final(self).position() == end
                    &&& end == old(self).position() + content.len()
                    &&& final(self).buffered().len() == if end > old(self).buffered().len() {
                        end as int
                    } else { old(self).buffered().len() as int }
                    &&& forall|i: int| 0 <= i < final(self).buffered().len() ==> final(self).buffered()[i] ==
                        if old(self).position() <= i < end { content@[i - old(self).position()] }
                        else if i < old(self).buffered().len() { old(self).buffered()[i] }
                        else { 0u8 }
                },
            },
    {
        let end = match self.write_range(content.len()) {
            WriteRange::End(end) => end,
            other => return other,
        };
        if end > self.bytes.len() { self.bytes.resize(end, 0); }
        let (_, tail) = self.bytes.as_mut_slice().split_at_mut(self.offset);
        let (destination, _) = tail.split_at_mut(content.len());
        destination.copy_from_slice(content);
        self.offset = end;
        self.dirty = true;
        WriteRange::End(end)
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
