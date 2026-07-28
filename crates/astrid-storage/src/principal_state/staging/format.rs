//! Versioned, checksummed publication-intent encoding.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use astrid_storage_engine::PrincipalCodec;
use uuid::Uuid;

use super::{StagedContentId, connection};
use crate::content::{ChunkingProfile, ContentName};
use crate::error::StorageResult;
use crate::principal_state::native_io::validate_private_regular_file;
use crate::principal_state::{StateOwner, StateOwnerCodecV1};

const INTENT_MAGIC: &[u8; 16] = b"ASTRID-STAGE-V1\0";
const INTENT_VERSION: u16 = 1;
const CHECKSUM_BYTES: usize = 32;
const FOOTER_MAGIC: &[u8; 16] = b"ASTRID-STAGE-F1\0";
const FOOTER_VERSION: u16 = 1;
const FOOTER_BYTES: u64 = 32;
const FOOTER_BYTES_USIZE: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StagingIntent {
    pub(super) sequence: u64,
    pub(super) id: StagedContentId,
    pub(super) owner: StateOwner,
    pub(super) name: ContentName,
    pub(super) profile: ChunkingProfile,
    pub(super) logical_bytes: u64,
}

pub(super) fn encode_intent(intent: &StagingIntent) -> StorageResult<Vec<u8>> {
    let owner = StateOwnerCodecV1.encode(&intent.owner);
    let name = intent.name.as_str().as_bytes();
    let owner_length = u64::try_from(owner.len())
        .map_err(|_| connection("staged owner length overflow".to_owned()))?;
    let name_length = u64::try_from(name.len())
        .map_err(|_| connection("staged content-name length overflow".to_owned()))?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(INTENT_MAGIC);
    bytes.extend_from_slice(&INTENT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&intent.sequence.to_le_bytes());
    bytes.extend_from_slice(intent.id.0.as_bytes());
    bytes.extend_from_slice(&owner_length.to_le_bytes());
    bytes.extend_from_slice(&owner);
    bytes.extend_from_slice(&name_length.to_le_bytes());
    bytes.extend_from_slice(name);
    bytes.extend_from_slice(&intent.profile.minimum_bytes().to_le_bytes());
    bytes.extend_from_slice(&intent.profile.average_bytes().to_le_bytes());
    bytes.extend_from_slice(&intent.profile.maximum_bytes().to_le_bytes());
    bytes.extend_from_slice(&intent.profile.gear_seed().to_le_bytes());
    bytes.extend_from_slice(&intent.logical_bytes.to_le_bytes());
    let checksum = intent_checksum(&bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

pub(super) fn load_intent(path: &Path) -> StorageResult<StagingIntent> {
    validate_private_regular_file(path)?;
    let bytes = std::fs::read(path)
        .map_err(|error| connection(format!("read staged intent {}: {error}", path.display())))?;
    decode_intent(&bytes)
        .map_err(|error| connection(format!("decode staged intent {}: {error}", path.display())))
}

pub(super) fn append_generation_footer(
    file: &mut std::fs::File,
    intent: &StagingIntent,
) -> StorageResult<()> {
    let encoded = encode_intent(intent)?;
    let encoded_len = u64::try_from(encoded.len())
        .map_err(|_| connection("staged generation footer length overflow".to_owned()))?;
    let mut trailer = [0_u8; FOOTER_BYTES_USIZE];
    trailer[..FOOTER_MAGIC.len()].copy_from_slice(FOOTER_MAGIC);
    trailer[16..18].copy_from_slice(&FOOTER_VERSION.to_le_bytes());
    trailer[24..32].copy_from_slice(&encoded_len.to_le_bytes());
    file.seek(SeekFrom::End(0))
        .and_then(|_| file.write_all(&encoded))
        .and_then(|()| file.write_all(&trailer))
        .map_err(|error| connection(format!("append staged generation footer: {error}")))
}

pub(super) fn load_generation_footer(path: &Path) -> StorageResult<StagingIntent> {
    let physical_bytes = validate_private_regular_file(path)?;
    let trailer_offset = physical_bytes.checked_sub(FOOTER_BYTES).ok_or_else(|| {
        connection(format!(
            "staged generation {} has no footer",
            path.display()
        ))
    })?;
    let mut file = OpenOptions::new().read(true).open(path).map_err(|error| {
        connection(format!(
            "open staged generation footer {}: {error}",
            path.display()
        ))
    })?;
    file.seek(SeekFrom::Start(trailer_offset))
        .map_err(|error| connection(format!("seek staged generation footer: {error}")))?;
    let mut trailer = [0_u8; FOOTER_BYTES_USIZE];
    file.read_exact(&mut trailer)
        .map_err(|error| connection(format!("read staged generation footer: {error}")))?;
    if trailer[..16] != FOOTER_MAGIC[..] {
        return Err(connection(format!(
            "staged generation {} footer magic mismatch",
            path.display()
        )));
    }
    if u16::from_le_bytes([trailer[16], trailer[17]]) != FOOTER_VERSION {
        return Err(connection(format!(
            "staged generation {} footer version is unsupported",
            path.display()
        )));
    }
    if trailer[18..24] != [0; 6] {
        return Err(connection(format!(
            "staged generation {} footer reserved bytes are non-zero",
            path.display()
        )));
    }
    let intent_bytes = u64::from_le_bytes(
        trailer[24..32]
            .try_into()
            .map_err(|_| connection("staged footer length width mismatch".to_owned()))?,
    );
    let intent_offset = trailer_offset.checked_sub(intent_bytes).ok_or_else(|| {
        connection(format!(
            "staged generation {} footer length exceeds the file",
            path.display()
        ))
    })?;
    let intent_len = usize::try_from(intent_bytes)
        .map_err(|_| connection("staged footer is not addressable".to_owned()))?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(intent_len)
        .map_err(|_| connection("staged footer allocation failed".to_owned()))?;
    encoded.resize(intent_len, 0);
    file.seek(SeekFrom::Start(intent_offset))
        .and_then(|_| file.read_exact(&mut encoded))
        .map_err(|error| connection(format!("read staged generation intent footer: {error}")))?;
    let intent = decode_intent(&encoded).map_err(|error| {
        connection(format!(
            "decode staged generation footer {}: {error}",
            path.display()
        ))
    })?;
    if intent.logical_bytes != intent_offset {
        return Err(connection(format!(
            "staged generation {} footer does not follow its logical bytes",
            path.display()
        )));
    }
    Ok(intent)
}

pub(super) fn decode_intent(bytes: &[u8]) -> Result<StagingIntent, &'static str> {
    let payload_length = bytes
        .len()
        .checked_sub(CHECKSUM_BYTES)
        .ok_or("staged intent is truncated")?;
    let (payload, checksum) = bytes.split_at(payload_length);
    if checksum != intent_checksum(payload) {
        return Err("staged intent checksum mismatch");
    }
    let mut decoder = Decoder::new(payload);
    if decoder.take(INTENT_MAGIC.len())? != INTENT_MAGIC {
        return Err("staged intent magic mismatch");
    }
    if decoder.u16()? != INTENT_VERSION {
        return Err("unsupported staged intent version");
    }
    let sequence = decoder.u64()?;
    let id = StagedContentId(Uuid::from_bytes(decoder.array()?));
    let owner_length =
        usize::try_from(decoder.u64()?).map_err(|_| "staged owner is not addressable")?;
    let owner = StateOwnerCodecV1
        .decode(decoder.take(owner_length)?)
        .ok_or("invalid staged owner")?;
    let name_length =
        usize::try_from(decoder.u64()?).map_err(|_| "staged name is not addressable")?;
    let name = std::str::from_utf8(decoder.take(name_length)?)
        .map_err(|_| "staged name is not UTF-8")
        .and_then(|value| ContentName::new(value.to_owned()).map_err(|_| "invalid staged name"))?;
    let profile = ChunkingProfile::fastcdc_v2020(
        decoder.u32()?,
        decoder.u32()?,
        decoder.u32()?,
        decoder.u64()?,
    )
    .map_err(|_| "invalid staged chunking profile")?;
    let logical_bytes = decoder.u64()?;
    if !decoder.is_empty() {
        return Err("staged intent has trailing bytes");
    }
    Ok(StagingIntent {
        sequence,
        id,
        owner,
        name,
        profile,
        logical_bytes,
    })
}

fn intent_checksum(bytes: &[u8]) -> [u8; CHECKSUM_BYTES] {
    *blake3::Hasher::new_derive_key("astrid native content staging intent v1")
        .update(bytes)
        .finalize()
        .as_bytes()
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], &'static str> {
        let end = self
            .position
            .checked_add(length)
            .ok_or("staged intent length overflow")?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or("staged intent is truncated")?;
        self.position = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], &'static str> {
        self.take(N)?
            .try_into()
            .map_err(|_| "staged intent field has wrong length")
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        self.array().map(u16::from_le_bytes)
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        self.array().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Result<u64, &'static str> {
        self.array().map(u64::from_le_bytes)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}
