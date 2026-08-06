struct EngineContentSource<'a>(&'a TestEngine);

impl astrid_storage_content::ContentSource for EngineContentSource<'_> {
    type Error = DurableError;

    fn load_content_object(
        &self,
        id: ObjectId,
    ) -> Result<Option<ObjectRecord>, Self::Error> {
        self.0.object(id)
    }
}

fn activate_physical_authority(engine: &TestEngine) {
    let specification = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"contiguous representation test specification".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let (specification_id, _) = engine.persist_standalone_object(&specification).unwrap();
    engine
        .ensure_direct_representation_catalogue(specification_id, &[specification_id])
        .unwrap();
}

fn patterned_content(bytes: usize) -> Vec<u8> {
    (0..bytes)
        .map(|index| {
            let block = index / (64 * 1024);
            u8::try_from((index.wrapping_mul(31) ^ block.wrapping_mul(17)) & 0xff).unwrap()
        })
        .collect()
}

#[test]
fn contiguous_copy_publishes_virtual_chunks_and_reopens() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    activate_physical_authority(&engine);
    let content = patterned_content(2 * 1024 * 1024 + 17);
    let prepared = engine
        .prepare_contiguous_file(
            astrid_storage_content::ChunkingProfile::ASTRID_V1,
            u64::try_from(content.len()).unwrap(),
            std::io::Cursor::new(&content),
        )
        .unwrap();
    let descriptor = prepared.descriptor();
    let chunk_ids = prepared.payload.slices.keys().copied().collect::<Vec<_>>();
    let blob = prepared.payload.blob;
    {
        let inner = engine.inner.lock();
        assert!(chunk_ids.iter().all(|id| !inner.index.contains_key(id)));
    }

    let published = engine
        .publish_contiguous_copy(prepared, std::io::Cursor::new(&content))
        .unwrap();
    assert_eq!(published.descriptor(), descriptor);
    assert!(chunk_ids.iter().all(|id| {
        engine
            .object(*id)
            .unwrap()
            .is_some_and(|record| record.kind() == ObjectKind::Chunk)
    }));
    assert_eq!(
        astrid_storage_content::read_content(&EngineContentSource(&engine), descriptor.file())
            .unwrap(),
        content
    );
    let blob_path = engine
        .inner
        .lock()
        .representations
        .as_ref()
        .unwrap()
        .loose_blob_path(blob, 1);
    assert!(blob_path.is_file());
    assert!(blob_path.with_extension("meta").is_file());
    engine.close().unwrap();
    drop(engine);

    let reopened = open(directory.path());
    assert_eq!(
        astrid_storage_content::read_content(&EngineContentSource(&reopened), descriptor.file())
            .unwrap(),
        content
    );
}

#[test]
fn contiguous_recovery_rejects_tampered_blob() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    activate_physical_authority(&engine);
    let content = patterned_content(512 * 1024 + 3);
    let prepared = engine
        .prepare_contiguous_file(
            astrid_storage_content::ChunkingProfile::ASTRID_V1,
            u64::try_from(content.len()).unwrap(),
            std::io::Cursor::new(&content),
        )
        .unwrap();
    let blob = prepared.payload.blob;
    engine
        .publish_contiguous_copy(prepared, std::io::Cursor::new(&content))
        .unwrap();
    let blob_path = engine
        .inner
        .lock()
        .representations
        .as_ref()
        .unwrap()
        .loose_blob_path(blob, 1);
    engine.close().unwrap();
    drop(engine);

    let mut file = OpenOptions::new().write(true).open(blob_path).unwrap();
    file.write_all(b"tamper").unwrap();
    file.sync_all().unwrap();
    drop(file);

    assert!(matches!(
        DurableEngine::<String, TestIdentity, Utf8Codec>::open(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            limits(),
        ),
        Err(DurableError::InvalidRepresentationState(_))
    ));
}

#[test]
fn contiguous_path_adoption_preserves_the_sealed_source() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    activate_physical_authority(&engine);
    let content = patterned_content(1024 * 1024 + 9);
    let mut sealed = content.clone();
    sealed.extend_from_slice(b"staging intent and footer remain recoverable");
    let source_path = directory.path().join("sealed-generation");
    std::fs::write(&source_path, &sealed).unwrap();
    let prepared = engine
        .prepare_contiguous_file(
            astrid_storage_content::ChunkingProfile::ASTRID_V1,
            u64::try_from(content.len()).unwrap(),
            File::open(&source_path)
                .unwrap()
                .take(u64::try_from(content.len()).unwrap()),
        )
        .unwrap();
    let descriptor = prepared.descriptor();

    engine
        .publish_contiguous_from_path(prepared, &source_path)
        .unwrap();

    assert_eq!(std::fs::read(&source_path).unwrap(), sealed);
    assert_eq!(
        astrid_storage_content::read_content(&EngineContentSource(&engine), descriptor.file())
            .unwrap(),
        content
    );
}

#[cfg(unix)]
#[test]
fn contiguous_publication_rejects_a_symlink_at_the_canonical_blob_path() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    activate_physical_authority(&engine);
    let content = patterned_content(256 * 1024 + 7);
    let prepared = engine
        .prepare_contiguous_file(
            astrid_storage_content::ChunkingProfile::ASTRID_V1,
            u64::try_from(content.len()).unwrap(),
            std::io::Cursor::new(&content),
        )
        .unwrap();
    let blob_path = engine
        .inner
        .lock()
        .representations
        .as_ref()
        .unwrap()
        .loose_blob_path(prepared.payload.blob, 1);
    std::fs::create_dir_all(blob_path.parent().unwrap()).unwrap();
    let target = directory.path().join("outside-authority");
    std::fs::write(&target, &content).unwrap();
    std::os::unix::fs::symlink(&target, &blob_path).unwrap();

    assert!(matches!(
        engine.publish_contiguous_copy(prepared, std::io::Cursor::new(&content)),
        Err(DurableError::InvalidRepresentationState(_))
    ));
    assert_eq!(std::fs::read(target).unwrap(), content);
}

#[cfg(unix)]
#[test]
fn contiguous_reads_reject_a_blob_replaced_by_a_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    activate_physical_authority(&engine);
    let content = patterned_content(256 * 1024 + 11);
    let prepared = engine
        .prepare_contiguous_file(
            astrid_storage_content::ChunkingProfile::ASTRID_V1,
            u64::try_from(content.len()).unwrap(),
            std::io::Cursor::new(&content),
        )
        .unwrap();
    let chunk = *prepared.payload.slices.keys().next().unwrap();
    let blob_path = engine
        .inner
        .lock()
        .representations
        .as_ref()
        .unwrap()
        .loose_blob_path(prepared.payload.blob, 1);
    engine
        .publish_contiguous_copy(prepared, std::io::Cursor::new(&content))
        .unwrap();
    let replacement = directory.path().join("redirected-blob");
    std::fs::write(&replacement, &content).unwrap();
    std::fs::remove_file(&blob_path).unwrap();
    std::os::unix::fs::symlink(&replacement, &blob_path).unwrap();

    assert!(matches!(
        engine.object(chunk),
        Err(DurableError::InvalidRepresentationState(_))
    ));
}

#[test]
fn contiguous_publication_rejects_wrong_bytes_at_the_canonical_blob_path() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    activate_physical_authority(&engine);
    let content = patterned_content(256 * 1024 + 13);
    let prepared = engine
        .prepare_contiguous_file(
            astrid_storage_content::ChunkingProfile::ASTRID_V1,
            u64::try_from(content.len()).unwrap(),
            std::io::Cursor::new(&content),
        )
        .unwrap();
    let blob_path = engine
        .inner
        .lock()
        .representations
        .as_ref()
        .unwrap()
        .loose_blob_path(prepared.payload.blob, 1);
    std::fs::create_dir_all(blob_path.parent().unwrap()).unwrap();
    std::fs::write(&blob_path, vec![0xff; content.len()]).unwrap();

    assert!(matches!(
        engine.publish_contiguous_copy(prepared, std::io::Cursor::new(&content)),
        Err(DurableError::InvalidRepresentationState(_))
    ));
    assert_eq!(std::fs::read(blob_path).unwrap(), vec![0xff; content.len()]);
}

#[test]
fn occupied_blob_reuse_still_verifies_the_supplied_complete_preimage() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    activate_physical_authority(&engine);
    let content = patterned_content(256 * 1024 + 29);
    let prepared = engine
        .prepare_contiguous_file(
            astrid_storage_content::ChunkingProfile::ASTRID_V1,
            u64::try_from(content.len()).unwrap(),
            std::io::Cursor::new(&content),
        )
        .unwrap();
    engine
        .publish_contiguous_copy(prepared, std::io::Cursor::new(&content))
        .unwrap();
    let retry = engine
        .prepare_contiguous_file(
            astrid_storage_content::ChunkingProfile::ASTRID_V1,
            u64::try_from(content.len()).unwrap(),
            std::io::Cursor::new(&content),
        )
        .unwrap();
    let different = vec![0x5a; content.len()];

    assert!(matches!(
        engine.publish_contiguous_copy(retry, std::io::Cursor::new(different)),
        Err(DurableError::InvalidRepresentationState(_))
    ));
}

#[test]
fn contiguous_recovery_rejects_tampered_loose_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    activate_physical_authority(&engine);
    let content = patterned_content(256 * 1024 + 5);
    let prepared = engine
        .prepare_contiguous_file(
            astrid_storage_content::ChunkingProfile::ASTRID_V1,
            u64::try_from(content.len()).unwrap(),
            std::io::Cursor::new(&content),
        )
        .unwrap();
    let blob = prepared.payload.blob;
    engine
        .publish_contiguous_copy(prepared, std::io::Cursor::new(&content))
        .unwrap();
    let metadata_path = engine
        .inner
        .lock()
        .representations
        .as_ref()
        .unwrap()
        .loose_blob_path(blob, 1)
        .with_extension("meta");
    engine.close().unwrap();
    drop(engine);

    let mut metadata = OpenOptions::new().write(true).open(metadata_path).unwrap();
    metadata.seek(SeekFrom::Start(20)).unwrap();
    metadata.write_all(&[0; 32]).unwrap();
    metadata.sync_all().unwrap();
    drop(metadata);

    assert!(matches!(
        DurableEngine::<String, TestIdentity, Utf8Codec>::open(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            limits(),
        ),
        Err(DurableError::InvalidRepresentationState(_))
    ));
}

#[test]
fn every_contiguous_publication_prefix_reopens_and_retries() {
    for point in [
        FaultPoint::AfterContiguousStructuralFlush,
        FaultPoint::AfterContiguousBlobInstall,
        FaultPoint::AfterContiguousMetadataAppend,
        FaultPoint::AfterContiguousStatePublish,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let bootstrap = open(directory.path());
        activate_physical_authority(&bootstrap);
        bootstrap.close().unwrap();
        drop(bootstrap);
        let content = patterned_content(384 * 1024 + 11);
        let mut sealed = content.clone();
        sealed.extend_from_slice(b"durable staging footer");
        let source_path = directory.path().join("sealed-generation");
        std::fs::write(&source_path, &sealed).unwrap();

        let engine = open_with_fault(directory.path(), point);
        let prepared = engine
            .prepare_contiguous_file(
                astrid_storage_content::ChunkingProfile::ASTRID_V1,
                u64::try_from(content.len()).unwrap(),
                File::open(&source_path)
                    .unwrap()
                    .take(u64::try_from(content.len()).unwrap()),
            )
            .unwrap();
        assert!(
            engine
                .publish_contiguous_from_path(prepared, &source_path)
                .is_err(),
            "{point:?}"
        );
        assert_eq!(std::fs::read(&source_path).unwrap(), sealed, "{point:?}");
        drop(engine);

        let reopened = open(directory.path());
        let prepared = reopened
            .prepare_contiguous_file(
                astrid_storage_content::ChunkingProfile::ASTRID_V1,
                u64::try_from(content.len()).unwrap(),
                File::open(&source_path)
                    .unwrap()
                    .take(u64::try_from(content.len()).unwrap()),
            )
            .unwrap();
        let descriptor = prepared.descriptor();
        reopened
            .publish_contiguous_from_path(prepared, &source_path)
            .unwrap();
        assert_eq!(
            astrid_storage_content::read_content(
                &EngineContentSource(&reopened),
                descriptor.file(),
            )
            .unwrap(),
            content,
            "{point:?}"
        );
    }
}
