//! Keep each accepted group and its persistence result together through publication.
use vstd::prelude::*;

verus! {

/// Preserve submission order when gathering the legacy root journal frames.
pub(super) fn journals<'a,T,F:Fn(&'a T)->&'a [u8]>(group:&'a [T],select:F)
    -> (out:Vec<&'a [u8]>)
    requires forall|i:int| 0 <= i < group.len() ==> #[trigger] select.requires((&group@[i],)),
    ensures out.len() == group.len(), forall|i:int| 0 <= i < group.len() ==>
        #[trigger] select.ensures((&group@[i],),out@[i]),
{
    let mut frames = Vec::with_capacity(group.len());
    let mut i = 0;
    while i < group.len()
        invariant i <= group.len(), frames.len() == i,
            forall|j:int| 0 <= j < group.len() ==> #[trigger] select.requires((&group@[j],)),
            forall|j:int| 0 <= j < i ==> #[trigger] select.ensures((&group@[j],),frames@[j]),
        decreases group.len()-i,
    {
        frames.push(select(&group[i]));
        i = i.saturating_add(1);
    }
    frames
}

/// Select the new cached WAL arena position after the filesystem length is read.
/// Equal lengths preserve the existing tail even when pending locations exist.
pub(super) fn wal_position<L: Copy>(current: u64, tail: Option<L>, observed: u64, pending: Option<L>)
    -> (position: Option<(u64, Option<L>)>)
    ensures
        position == if observed < current { None }
            else if observed == current { Some((current, tail)) }
            else { Some((observed, if pending.is_some() { pending } else { tail })) },
{
    match observed.cmp(&current) {
        std::cmp::Ordering::Less => None,
        std::cmp::Ordering::Equal => Some((current, tail)),
        std::cmp::Ordering::Greater => Some((observed, match pending { Some(location) => Some(location), None => tail })),
    }
}

pub(super) trait JournalContainer {
    type Error;
    spec fn journal_image(&self) -> Seq<u8>;
    spec fn durable_image(&self) -> Seq<u8>;
    spec fn container_id(&self) -> int;
    spec fn region_id(&self) -> Seq<u8>;
    spec fn sync_failed(&self,error:Self::Error) -> bool;
    fn sync_container(&mut self) -> (out:Result<(),Self::Error>)
        ensures final(self).container_id()==old(self).container_id(), final(self).region_id()==old(self).region_id(),
            out.is_ok() ==> final(self).durable_image()==old(self).journal_image(),
            out matches Err(e) ==> old(self).sync_failed(e);
}

#[derive(Debug)]
pub(super) enum JournalFlush<C> { StableFile, AwaitingContainer(C) }
#[cfg(verus_keep_ghost)]
pub(super) ghost enum JournalCall<C,E> { Write(Seq<u8>,Result<(),E>), Sync(Result<JournalFlush<C>,E>) }

/// A journal handle positioned at the append offset. A failed host operation may
/// leave partial bytes. Only a successful sync certifies the complete pending image.
pub(super) trait JournalSink {
    type Error;
    type Container: JournalContainer<Error=Self::Error>;
    spec fn pending(&self) -> Seq<u8>;
    spec fn durable(&self) -> Seq<u8>;
    spec fn position(&self) -> int;
    spec fn journal_target(&self) -> (int,Seq<u8>);
    spec fn journal_calls(&self) -> Seq<JournalCall<Self::Container,Self::Error>>;
    fn write_batch(&mut self,bytes:&[u8]) -> (out:Result<(),Self::Error>)
        ensures final(self).journal_target()==old(self).journal_target(),
            final(self).journal_calls()==old(self).journal_calls().push(JournalCall::Write(bytes@,out)),
            out.is_ok() && old(self).position()==old(self).pending().len()
            ==> final(self).pending()==old(self).pending()+bytes@;
    fn flush_batch(&mut self) -> (out:Result<JournalFlush<Self::Container>,Self::Error>)
        ensures final(self).journal_target()==old(self).journal_target(),
            final(self).journal_calls()==old(self).journal_calls().push(JournalCall::Sync(out)),
            out matches Ok(JournalFlush::StableFile) ==> final(self).durable()==old(self).pending(),
            out matches Ok(JournalFlush::AwaitingContainer(c)) ==> (c.container_id(),c.region_id())==old(self).journal_target() &&
                c.journal_image()==old(self).pending() && final(self).pending()==old(self).pending();
}

pub(super) open spec fn journal_completed<C,E>(prior:Seq<JournalCall<C,E>>,after:Seq<JournalCall<C,E>>,batch:Seq<u8>,out:Result<JournalFlush<C>,E>) -> bool {
    let submitted=prior.push(JournalCall::Write(batch,Ok(())));
    after==submitted.push(JournalCall::Sync(out)) ||
        (out matches Err(e) && after==prior.push(JournalCall::Write(batch,Err(e))))
}

/// Use the same journal handle for both operations and propagate its first error.
pub(super) fn persist_journal<S:JournalSink>(sink:&mut S,bytes:&[u8]) -> (out:Result<JournalFlush<S::Container>,S::Error>)
    ensures journal_completed(old(sink).journal_calls(),final(sink).journal_calls(),bytes@,out),
        final(sink).journal_target()==old(sink).journal_target(),
        out matches Ok(JournalFlush::AwaitingContainer(c)) ==> (c.container_id(),c.region_id())==old(sink).journal_target(),
        old(sink).position()==old(sink).pending().len() ==> match out {
            Ok(JournalFlush::StableFile)=>final(sink).durable()==old(sink).pending()+bytes@,
            Ok(JournalFlush::AwaitingContainer(c))=>c.journal_image()==old(sink).pending()+bytes@,
            Err(_)=>true,
        },
{
    sink.write_batch(bytes)?;
    sink.flush_batch()
}

/// Publish the index before flushing the exact container retained by the root journal.
pub(super) fn finish_journal<C:JournalContainer,F:FnOnce()->Result<(),C::Error>>(receipt:JournalFlush<C>,advance:F)
    -> (out:Result<Option<C>,C::Error>)
    requires advance.requires(()),
    ensures out.is_ok() ==> advance.ensures((),Ok(())),
        out matches Ok(None) ==> receipt is StableFile,
        out matches Ok(Some(stable)) ==> receipt matches JournalFlush::AwaitingContainer(submitted)
            && stable.durable_image()==submitted.journal_image() && stable.container_id()==submitted.container_id()
            && stable.region_id()==submitted.region_id(),
        out matches Err(e) ==> advance.ensures((),Err(e)) || (advance.ensures((),Ok(())) &&
            (receipt matches JournalFlush::AwaitingContainer(c) && c.sync_failed(e))),
{
    advance()?;
    match receipt {
        JournalFlush::StableFile=>Ok(None),
        JournalFlush::AwaitingContainer(mut c)=>{c.sync_container()?;Ok(Some(c))}
    }
}

/// `BufWriter::flush` writes pending bytes and flushes the underlying handle.
pub(super) enum WalDrain { File, Container }

pub(super) trait WalOutput {
    type Error;
    /// Logical WAL contents after writing the tail still held by the buffer.
    spec fn buffered_image(&self) -> Seq<u8>;
    spec fn wal_target(&self) -> (int,Seq<u8>);
    spec fn at_end(&self) -> bool;
    spec fn append_error(&self,e:Self::Error) -> bool;
    fn append_record(&mut self,bytes:&[u8]) -> (out:Result<(),Self::Error>)
        ensures final(self).wal_target()==old(self).wal_target(),
            out matches Err(e) ==> old(self).append_error(e),
            out.is_ok() && old(self).at_end() ==> final(self).at_end() &&
                final(self).buffered_image()==old(self).buffered_image()+bytes@;
}

pub(super) trait BufferedWal:WalOutput {
    spec fn file_image(&self) -> Seq<u8>;
    spec fn stable_image(&self) -> Seq<u8>;
    spec fn drain_error(&self,e:Self::Error) -> bool;
    spec fn sync_error(&self,e:Self::Error) -> bool;
    fn drain(&mut self) -> (out:Result<WalDrain,Self::Error>)
        ensures final(self).wal_target()==old(self).wal_target(),
            out matches Ok(WalDrain::File) ==> final(self).file_image()==old(self).buffered_image(),
            out matches Ok(WalDrain::Container) ==> final(self).stable_image()==old(self).buffered_image(),
            out matches Err(e) ==> old(self).drain_error(e);
    fn sync_file(&mut self) -> (out:Result<(),Self::Error>)
        ensures final(self).wal_target()==old(self).wal_target(),
            out.is_ok() ==> final(self).stable_image()==old(self).file_image(),
            out matches Err(e) ==> old(self).sync_error(e);
}

pub(super) fn publish_buffer<S:BufferedWal>(sink:&mut S) -> (out:Result<(),S::Error>)
    ensures final(sink).wal_target()==old(sink).wal_target(),
        out.is_ok() ==> final(sink).stable_image()==old(sink).buffered_image(),
        out matches Err(e) ==> old(sink).drain_error(e) ||
            exists|drained:S| drained.wal_target()==old(sink).wal_target() &&
                drained.file_image()==old(sink).buffered_image() && #[trigger] drained.sync_error(e),
{
    match sink.drain()? {
        WalDrain::File=>sink.sync_file(),
        WalDrain::Container=>Ok(()),
    }
}

pub(super) enum PublicationError<E> { Active, Empty, Sync(E) }

/// Consume the pending count only after the actual writer sync succeeds.
pub(super) fn sync_pending<T,E,F>(active: bool, pending: &mut u64, poisoned: &mut bool, sync: F)
    -> (outcome: Result<(u64,T), PublicationError<E>>)
    where F: FnOnce() -> Result<T, E>,
    requires sync.requires(()),
    ensures
        (outcome matches Err(PublicationError::Active)) == active,
        (outcome matches Err(PublicationError::Empty)) == (!active && *old(pending) == 0),
        outcome matches Ok((n,receipt)) ==> n == *old(pending) && n > 0 && !active
            && sync.ensures((),Ok(receipt)),
        outcome matches Err(PublicationError::Sync(error)) ==> !active && *old(pending) > 0
            && sync.ensures((), Err(error)),
        *final(pending) == if outcome.is_ok() { 0 } else { *old(pending) },
        *final(poisoned) == (*old(poisoned) || outcome matches Err(PublicationError::Sync(_))),
{
    if active { return Err(PublicationError::Active); }
    if *pending == 0 { return Err(PublicationError::Empty); }
    let receipt = match sync() {
        Ok(value) => value,
        Err(error) => {
            *poisoned = true;
            return Err(PublicationError::Sync(error));
        }
    };
    let count = *pending;
    *pending = 0;
    Ok((count,receipt))
}

pub(super) struct PersistedGroup<B, D> {
    batch: B,
    durable: D,
}

impl<B, D> PersistedGroup<B, D> {
    pub(super) closed spec fn binding(&self) -> (B, D) {
        (self.batch, self.durable)
    }

    pub(super) fn persist<E, F>(batch: B, persist: F) -> (result: Result<Self, (B, E)>)
        where F: FnOnce(&B) -> Result<D, E>,
        requires persist.requires((&batch,)),
        ensures
            result matches Ok(group) ==> group.binding().0 == batch
                && persist.ensures((&batch,), Ok(group.binding().1)),
            result matches Err((submitted, error)) ==> submitted == batch
                && persist.ensures((&batch,), Err(error)),
    {
        match persist(&batch) {
            Ok(durable) => Ok(Self { batch, durable }),
            Err(error) => Err((batch, error)),
        }
    }

    pub(super) fn publish<T, E, F>(self, advance: F) -> (result: Result<(B, T), (B, E)>)
        where F: FnOnce(D) -> Result<T, E>,
        requires advance.requires((self.binding().1,)),
        ensures
            result matches Ok((batch, frontier)) ==> batch == self.binding().0
                && advance.ensures((self.binding().1,), Ok(frontier)),
            result matches Err((submitted, error)) ==> submitted == self.binding().0
                && advance.ensures((self.binding().1,), Err(error)),
    {
        match advance(self.durable) {
            Ok(frontier) => Ok((self.batch, frontier)),
            Err(error) => Err((self.batch, error)),
        }
    }
}

}
