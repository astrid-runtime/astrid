//! Versioned, checksummed publication-intent encoding.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::engine::PrincipalCodec;
use astrid_core::principal::PrincipalId;
use uuid::Uuid;

use super::{StagedContentId, connection};
use crate::content::{ChunkingProfile, ContentName};
use crate::error::{StorageError, StorageResult};
use crate::principal_state::native_io::{
    PrivateFileIdentity, open_private_file, validate_private_regular_file,
};
use crate::principal_state::{
    RuntimeStateOwnerCodecV2, StateOwner, StateOwnerCodecV2, ensure_runtime_state_owner_admitted,
};

pub(super) const INTENT_MAGIC: &[u8; 16] = b"ASTRID-STAGE-V2\0";
pub(super) const INTENT_VERSION: u16 = 2;
const LEGACY_INTENT_MAGIC: &[u8; 16] = b"ASTRID-STAGE-V1\0";
const LEGACY_INTENT_VERSION: u16 = 1;
const CHECKSUM_BYTES: usize = 32;
pub(super) const FOOTER_MAGIC: &[u8; 16] = b"ASTRID-STAGE-F1\0";
pub(super) const FOOTER_VERSION: u16 = 1;
pub(super) const FOOTER_BYTES: u64 = 32;
const FOOTER_BYTES_USIZE: usize = 32;
const SOURCE_IDENTITY_BYTES: u64 = 16;
const SOURCE_BINDING_CHECKSUM_BYTES: u64 = 32;
const FASTCDC_2020_ALGORITHM: u8 = 1;
const FASTCDC_IMPLEMENTATION_REVISION: u16 = 1;
const FASTCDC_NORMALIZATION: u8 = 1;
pub(super) const USER_OWNER_NOT_ADMITTED: &str =
    "user staged owner is not admitted by runtime owner codec V2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StagingIntent {
    pub(super) sequence: u64,
    pub(super) id: StagedContentId,
    pub(super) owner: StateOwner,
    pub(super) name: ContentName,
    pub(super) profile: ChunkingProfile,
    pub(super) logical_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum LegacyStagingOwner {
    System,
    Principal(PrincipalId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LegacyStagingIntent {
    pub(super) sequence: u64,
    pub(super) id: StagedContentId,
    pub(super) owner: LegacyStagingOwner,
    pub(super) name: ContentName,
    pub(super) profile: ChunkingProfile,
    pub(super) logical_bytes: u64,
}

pub(super) fn encode_intent(intent: &StagingIntent) -> StorageResult<Vec<u8>> {
    ensure_runtime_state_owner_admitted(&intent.owner)?;
    let owner = RuntimeStateOwnerCodecV2.encode(&intent.owner);
    encode_fields(
        INTENT_MAGIC,
        INTENT_VERSION,
        intent.sequence,
        intent.id,
        &owner,
        &intent.name,
        intent.profile,
        intent.logical_bytes,
        "astrid native content staging intent v2",
        true,
    )
}

#[cfg(test)]
pub(super) fn encode_legacy_intent(intent: &LegacyStagingIntent) -> StorageResult<Vec<u8>> {
    let owner = match &intent.owner {
        LegacyStagingOwner::System => vec![0],
        LegacyStagingOwner::Principal(principal) => {
            let mut bytes = Vec::with_capacity(principal.as_str().len().saturating_add(1));
            bytes.push(1);
            bytes.extend_from_slice(principal.as_str().as_bytes());
            bytes
        },
    };
    encode_fields(
        LEGACY_INTENT_MAGIC,
        LEGACY_INTENT_VERSION,
        intent.sequence,
        intent.id,
        &owner,
        &intent.name,
        intent.profile,
        intent.logical_bytes,
        "astrid native content staging intent v1",
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn encode_fields(
    magic: &[u8; 16],
    version: u16,
    sequence: u64,
    id: StagedContentId,
    owner: &[u8],
    name: &ContentName,
    profile: ChunkingProfile,
    logical_bytes: u64,
    checksum_context: &'static str,
    tagged_profile: bool,
) -> StorageResult<Vec<u8>> {
    let name = name.as_str().as_bytes();
    let owner_length = u64::try_from(owner.len())
        .map_err(|_| connection("staged owner length overflow".to_owned()))?;
    let name_length = u64::try_from(name.len())
        .map_err(|_| connection("staged content-name length overflow".to_owned()))?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(id.0.as_bytes());
    bytes.extend_from_slice(&owner_length.to_le_bytes());
    bytes.extend_from_slice(owner);
    bytes.extend_from_slice(&name_length.to_le_bytes());
    bytes.extend_from_slice(name);
    if tagged_profile {
        bytes.push(FASTCDC_2020_ALGORITHM);
        bytes.extend_from_slice(&FASTCDC_IMPLEMENTATION_REVISION.to_le_bytes());
        bytes.push(FASTCDC_NORMALIZATION);
    }
    bytes.extend_from_slice(&profile.minimum_bytes().to_le_bytes());
    bytes.extend_from_slice(&profile.average_bytes().to_le_bytes());
    bytes.extend_from_slice(&profile.maximum_bytes().to_le_bytes());
    bytes.extend_from_slice(&profile.gear_seed().to_le_bytes());
    bytes.extend_from_slice(&logical_bytes.to_le_bytes());
    let checksum = intent_checksum(checksum_context, &bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

pub(super) fn load_intent(path: &Path) -> StorageResult<StagingIntent> {
    validate_private_regular_file(path)?;
    let mut file = open_private_file(path)?;
    load_intent_from_file(path, &mut file)
}

pub(super) fn load_intent_from_file(
    path: &Path,
    file: &mut std::fs::File,
) -> StorageResult<StagingIntent> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| connection(format!("read staged intent {}: {error}", path.display())))?;
    decode_intent(&bytes)
        .map_err(|error| connection(format!("decode staged intent {}: {error}", path.display())))
}

pub(super) fn append_generation_footer(
    file: &mut std::fs::File,
    intent: &StagingIntent,
    source_identity: PrivateFileIdentity,
) -> StorageResult<()> {
    let encoded = encode_intent(intent)?;
    append_footer_bytes(file, &encoded, source_identity)
}

#[cfg(test)]
pub(super) fn append_runtime_forbidden_user_footer(
    file: &mut std::fs::File,
    intent: &StagingIntent,
    source_identity: PrivateFileIdentity,
) -> StorageResult<()> {
    let owner = StateOwnerCodecV2.encode(&intent.owner);
    let encoded = encode_fields(
        INTENT_MAGIC,
        INTENT_VERSION,
        intent.sequence,
        intent.id,
        &owner,
        &intent.name,
        intent.profile,
        intent.logical_bytes,
        "astrid native content staging intent v2",
        true,
    )?;
    append_footer_bytes(file, &encoded, source_identity)
}

fn append_footer_bytes(
    file: &mut std::fs::File,
    encoded: &[u8],
    source_identity: PrivateFileIdentity,
) -> StorageResult<()> {
    let payload_len = u64::try_from(encoded.len())
        .map_err(|_| connection("staged generation footer length overflow".to_owned()))?;
    let payload_len = payload_len
        .checked_add(SOURCE_IDENTITY_BYTES)
        .and_then(|length| length.checked_add(SOURCE_BINDING_CHECKSUM_BYTES))
        .ok_or_else(|| connection("staged generation footer length overflow".to_owned()))?;
    let source_identity = source_identity_bytes(source_identity);
    let source_binding = source_binding_checksum(encoded, &source_identity);
    let mut trailer = [0_u8; FOOTER_BYTES_USIZE];
    trailer[..FOOTER_MAGIC.len()].copy_from_slice(FOOTER_MAGIC);
    trailer[16..18].copy_from_slice(&FOOTER_VERSION.to_le_bytes());
    trailer[24..32].copy_from_slice(&payload_len.to_le_bytes());
    file.seek(SeekFrom::End(0))
        .and_then(|_| file.write_all(encoded))
        .and_then(|()| file.write_all(&source_identity))
        .and_then(|()| file.write_all(&source_binding))
        .and_then(|()| file.write_all(&trailer))
        .map_err(|error| connection(format!("append staged generation footer: {error}")))
}

pub(super) struct GenerationFooter {
    pub(super) intent: StagingIntent,
    pub(super) source_identity: PrivateFileIdentity,
}

pub(super) fn load_generation_footer_from_file(
    path: &Path,
    file: &mut std::fs::File,
) -> StorageResult<GenerationFooter> {
    let metadata = file.metadata().map_err(|error| {
        connection(format!(
            "inspect staged generation handle {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(connection(format!(
            "staged generation {} is not a regular file",
            path.display()
        )));
    }
    let physical_bytes = metadata.len();
    let trailer_offset = physical_bytes.checked_sub(FOOTER_BYTES).ok_or_else(|| {
        connection(format!(
            "staged generation {} has no footer",
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
    let footer_version = u16::from_le_bytes([trailer[16], trailer[17]]);
    if footer_version != FOOTER_VERSION {
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
    let payload_bytes = u64::from_le_bytes(
        trailer[24..32]
            .try_into()
            .map_err(|_| connection("staged footer length width mismatch".to_owned()))?,
    );
    let payload_offset = trailer_offset.checked_sub(payload_bytes).ok_or_else(|| {
        connection(format!(
            "staged generation {} footer length exceeds the file",
            path.display()
        ))
    })?;
    let payload_len = usize::try_from(payload_bytes)
        .map_err(|_| connection("staged footer is not addressable".to_owned()))?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_len)
        .map_err(|_| connection("staged footer allocation failed".to_owned()))?;
    payload.resize(payload_len, 0);
    file.seek(SeekFrom::Start(payload_offset))
        .and_then(|_| file.read_exact(&mut payload))
        .map_err(|error| connection(format!("read staged generation intent footer: {error}")))?;
    let footer = decode_generation_footer_payload(path, &payload)?;
    if footer.intent.logical_bytes != payload_offset {
        return Err(connection(format!(
            "staged generation {} footer does not follow its logical bytes",
            path.display()
        )));
    }
    Ok(footer)
}

/// Classify a footer owner in fixed memory before trusting its declared size.
pub(super) enum GenerationOwnerScan {
    User,
    Admitted,
    Terminal,
    Malformed(&'static str),
}

pub(super) fn inspect_generation_footer_owner(
    path: &Path,
    file: &mut std::fs::File,
) -> StorageResult<GenerationOwnerScan> {
    const EARLY_PREFIX_BYTES: usize = 16 + 2 + 8 + 16 + 8;
    const OWNER_BYTES: usize = 33;
    const MINIMUM_PAYLOAD_BYTES: u64 = (EARLY_PREFIX_BYTES + OWNER_BYTES + CHECKSUM_BYTES) as u64;
    let metadata = file.metadata().map_err(|error| {
        connection(format!(
            "inspect staged generation handle {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(connection(format!(
            "staged generation {} is not a regular file",
            path.display()
        )));
    }
    let physical_bytes = metadata.len();
    let Some(trailer_offset) = physical_bytes.checked_sub(FOOTER_BYTES) else {
        return Ok(GenerationOwnerScan::Terminal);
    };
    file.seek(SeekFrom::Start(trailer_offset))
        .map_err(|error| connection(format!("seek staged generation footer: {error}")))?;
    let mut trailer = [0_u8; FOOTER_BYTES_USIZE];
    file.read_exact(&mut trailer)
        .map_err(|error| connection(format!("read staged generation footer: {error}")))?;
    if trailer[..16] != FOOTER_MAGIC[..] {
        return Ok(GenerationOwnerScan::Malformed("footer magic mismatch"));
    }
    if u16::from_le_bytes([trailer[16], trailer[17]]) != FOOTER_VERSION {
        return Ok(GenerationOwnerScan::Malformed(
            "footer version is unsupported",
        ));
    }
    if trailer[18..24] != [0; 6] {
        return Ok(GenerationOwnerScan::Malformed(
            "footer reserved bytes are non-zero",
        ));
    }
    let payload_bytes = u64::from_le_bytes(
        trailer[24..32]
            .try_into()
            .map_err(|_| connection("staged footer length width mismatch".to_owned()))?,
    );
    let payload_offset = trailer_offset.checked_sub(payload_bytes).ok_or_else(|| {
        connection(format!(
            "staged generation {} footer length exceeds the file",
            path.display()
        ))
    })?;
    if payload_bytes < MINIMUM_PAYLOAD_BYTES {
        return Ok(GenerationOwnerScan::Malformed("staged intent is truncated"));
    }
    file.seek(SeekFrom::Start(payload_offset))
        .map_err(|error| connection(format!("seek staged generation owner: {error}")))?;
    let mut early = [0_u8; EARLY_PREFIX_BYTES];
    file.read_exact(&mut early)
        .map_err(|error| connection(format!("read staged generation owner prefix: {error}")))?;
    if early[..16] != INTENT_MAGIC[..]
        || u16::from_le_bytes([early[16], early[17]]) != INTENT_VERSION
    {
        return Ok(GenerationOwnerScan::Malformed(
            "staged intent magic or version is invalid",
        ));
    }
    let owner_len = u64::from_le_bytes(
        early[42..50]
            .try_into()
            .expect("fixed-width staging owner length"),
    );
    if owner_len != OWNER_BYTES as u64 {
        return Ok(GenerationOwnerScan::Malformed(
            "staged owner has invalid length",
        ));
    }
    let mut owner = [0_u8; OWNER_BYTES];
    file.read_exact(&mut owner)
        .map_err(|error| connection(format!("read staged generation owner: {error}")))?;
    match StateOwnerCodecV2.decode(&owner) {
        Some(crate::principal_state::StateOwner::User(_)) => Ok(GenerationOwnerScan::User),
        Some(_) => match load_generation_footer_from_file(path, file) {
            Ok(_) => Ok(GenerationOwnerScan::Admitted),
            Err(error) if is_runtime_forbidden_user_owner(&error) => Ok(GenerationOwnerScan::User),
            Err(error) => Err(connection(format!(
                "staged generation {} footer could not prove full integrity: {error}",
                path.display()
            ))),
        },
        None => Ok(GenerationOwnerScan::Malformed(
            "staged owner is not canonical StateOwner V2",
        )),
    }
}

/// Distinguish the reserved wire tag from malformed or torn staging bytes.
pub(super) fn is_runtime_forbidden_user_owner(error: &StorageError) -> bool {
    error.to_string().contains(USER_OWNER_NOT_ADMITTED)
}

pub(super) fn is_runtime_forbidden_user_intent_error(error: &'static str) -> bool {
    error == USER_OWNER_NOT_ADMITTED
}

fn decode_generation_footer_payload(
    path: &Path,
    payload: &[u8],
) -> StorageResult<GenerationFooter> {
    let binding_bytes = SOURCE_IDENTITY_BYTES
        .checked_add(SOURCE_BINDING_CHECKSUM_BYTES)
        .ok_or_else(|| connection("staged footer binding length overflow".to_owned()))?;
    let identity_offset = payload
        .len()
        .checked_sub(usize::try_from(binding_bytes).unwrap_or(usize::MAX))
        .ok_or_else(|| connection("staged footer source identity is truncated".to_owned()))?;
    let (encoded, binding) = payload.split_at(identity_offset);
    let (identity, checksum) = binding.split_at(
        usize::try_from(SOURCE_IDENTITY_BYTES)
            .map_err(|_| connection("staged footer identity is not addressable".to_owned()))?,
    );
    if checksum != source_binding_checksum(encoded, identity) {
        return Err(connection(format!(
            "staged generation {} source binding checksum mismatch",
            path.display()
        )));
    }
    let volume = u64::from_le_bytes(
        identity[..8]
            .try_into()
            .map_err(|_| connection("staged footer source volume width mismatch".to_owned()))?,
    );
    let file = u64::from_le_bytes(
        identity[8..]
            .try_into()
            .map_err(|_| connection("staged footer source file width mismatch".to_owned()))?,
    );
    let source_identity = PrivateFileIdentity::from_raw_parts(volume, file);
    let intent = decode_intent(encoded).map_err(|error| {
        connection(format!(
            "decode staged generation footer {}: {error}",
            path.display()
        ))
    })?;
    Ok(GenerationFooter {
        intent,
        source_identity,
    })
}

pub(super) fn source_identity_bytes(identity: PrivateFileIdentity) -> [u8; 16] {
    let (volume, file) = identity.raw_parts();
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&volume.to_le_bytes());
    bytes[8..].copy_from_slice(&file.to_le_bytes());
    bytes
}

pub(super) fn source_binding_checksum(encoded_intent: &[u8], identity: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("astrid staged source binding v1");
    hasher.update(encoded_intent);
    hasher.update(identity);
    *hasher.finalize().as_bytes()
}

pub(super) fn decode_intent(bytes: &[u8]) -> Result<StagingIntent, &'static str> {
    let fields = decode_fields(
        bytes,
        INTENT_MAGIC,
        INTENT_VERSION,
        "astrid native content staging intent v2",
        true,
    )?;
    let owner = StateOwnerCodecV2
        .decode(&fields.owner)
        .ok_or("invalid staged owner")?;
    if matches!(owner, StateOwner::User(_)) {
        return Err(USER_OWNER_NOT_ADMITTED);
    }
    Ok(StagingIntent {
        sequence: fields.sequence,
        id: fields.id,
        owner,
        name: fields.name,
        profile: fields.profile,
        logical_bytes: fields.logical_bytes,
    })
}

pub(super) fn load_legacy_intent(path: &Path) -> StorageResult<LegacyStagingIntent> {
    validate_private_regular_file(path)?;
    let bytes = std::fs::read(path).map_err(|error| {
        connection(format!(
            "read legacy staged intent {}: {error}",
            path.display()
        ))
    })?;
    decode_legacy_intent(&bytes).map_err(|error| {
        connection(format!(
            "decode legacy staged intent {}: {error}",
            path.display()
        ))
    })
}

pub(super) fn decode_legacy_intent(bytes: &[u8]) -> Result<LegacyStagingIntent, &'static str> {
    let fields = decode_fields(
        bytes,
        LEGACY_INTENT_MAGIC,
        LEGACY_INTENT_VERSION,
        "astrid native content staging intent v1",
        false,
    )?;
    let owner = match fields.owner.split_first() {
        Some((0, [])) => LegacyStagingOwner::System,
        Some((1, principal)) => std::str::from_utf8(principal)
            .map_err(|_| "legacy staged principal is not UTF-8")
            .and_then(|value| {
                PrincipalId::new(value.to_owned()).map_err(|_| "invalid legacy staged principal")
            })
            .map(LegacyStagingOwner::Principal)?,
        _ => return Err("invalid legacy staged owner"),
    };
    Ok(LegacyStagingIntent {
        sequence: fields.sequence,
        id: fields.id,
        owner,
        name: fields.name,
        profile: fields.profile,
        logical_bytes: fields.logical_bytes,
    })
}

struct DecodedIntentFields {
    sequence: u64,
    id: StagedContentId,
    owner: Vec<u8>,
    name: ContentName,
    profile: ChunkingProfile,
    logical_bytes: u64,
}

fn decode_fields(
    bytes: &[u8],
    magic: &[u8; 16],
    version: u16,
    checksum_context: &'static str,
    tagged_profile: bool,
) -> Result<DecodedIntentFields, &'static str> {
    let payload_length = bytes
        .len()
        .checked_sub(CHECKSUM_BYTES)
        .ok_or("staged intent is truncated")?;
    let (payload, checksum) = bytes.split_at(payload_length);
    if checksum != intent_checksum(checksum_context, payload) {
        return Err("staged intent checksum mismatch");
    }
    let mut decoder = Decoder::new(payload);
    if decoder.take(magic.len())? != magic {
        return Err("staged intent magic mismatch");
    }
    if decoder.u16()? != version {
        return Err("unsupported staged intent version");
    }
    let sequence = decoder.u64()?;
    let id = StagedContentId(Uuid::from_bytes(decoder.array()?));
    let owner_length =
        usize::try_from(decoder.u64()?).map_err(|_| "staged owner is not addressable")?;
    let owner = decoder.take(owner_length)?.to_vec();
    let name_length =
        usize::try_from(decoder.u64()?).map_err(|_| "staged name is not addressable")?;
    let name = std::str::from_utf8(decoder.take(name_length)?)
        .map_err(|_| "staged name is not UTF-8")
        .and_then(|value| ContentName::new(value.to_owned()).map_err(|_| "invalid staged name"))?;
    if tagged_profile
        && (decoder.u8()? != FASTCDC_2020_ALGORITHM
            || decoder.u16()? != FASTCDC_IMPLEMENTATION_REVISION
            || decoder.u8()? != FASTCDC_NORMALIZATION)
    {
        return Err("unsupported staged chunking construction");
    }
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
    Ok(DecodedIntentFields {
        sequence,
        id,
        owner,
        name,
        profile,
        logical_bytes,
    })
}

fn intent_checksum(context: &'static str, bytes: &[u8]) -> [u8; CHECKSUM_BYTES] {
    *blake3::Hasher::new_derive_key(context)
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

    fn u8(&mut self) -> Result<u8, &'static str> {
        self.array().map(u8::from_le_bytes)
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

#[cfg(test)]
mod tests {
    use super::{
        INTENT_MAGIC, INTENT_VERSION, StagedContentId, USER_OWNER_NOT_ADMITTED, decode_intent,
        encode_fields,
    };
    use crate::content::{ChunkingProfile, ContentName};
    use uuid::Uuid;

    #[test]
    fn recovery_rejects_forged_user_owner_without_decoding() {
        let mut owner = vec![3];
        owner.extend_from_slice(&[11; 32]);
        let bytes = encode_fields(
            INTENT_MAGIC,
            INTENT_VERSION,
            7,
            StagedContentId(Uuid::from_u128(11)),
            &owner,
            &ContentName::new("forged.bin").unwrap(),
            ChunkingProfile::ASTRID_V1,
            0,
            "astrid native content staging intent v2",
            true,
        )
        .unwrap();

        assert!(matches!(
            decode_intent(&bytes).unwrap_err(),
            USER_OWNER_NOT_ADMITTED
        ));
    }
}
