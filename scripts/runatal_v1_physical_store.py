"""Authoritative-store recovery for the independent RÚNATAL physical reader."""

import struct

from runatal_v1_physical import (
    ARENA_MAGIC,
    BLOB_CONTEXT,
    CATALOGUE_CONTEXT,
    CURRENT_MAGIC,
    JOURNAL_CONTEXT,
    JOURNAL_MAGIC,
    LOGICAL_SCHEME,
    MAP_CONTEXT,
    METADATA_MAGIC,
    PHYSICAL_SCHEME,
    PLACEMENT_CONTEXT,
    PROFILE_CONTEXT,
    RECORD_CONTEXT,
    STATE_CONTEXT,
    Cursor,
    FormatError,
    decode_catalogue_root,
    decode_map_node,
    decode_placement_entry,
    decode_placement_set,
    decode_profile,
    decode_representation,
    decode_representation_state,
    derive_key,
    frame_checksum,
    frames,
    identity,
    identity_bytes,
    identity_text,
    optional_identity,
    physical_frame,
    physical_identity,
    validate_map,
)


def decode_store(store, bootstrap_objects=()):
    """Recover and independently validate one authoritative physical store."""
    current_frames = list(frames(store / "representations" / "CURRENT", CURRENT_MAGIC))
    if len(current_frames) != 1 or current_frames[0][0] != 0:
        raise FormatError("representation CURRENT is not exactly one frame")
    cursor = Cursor(current_frames[0][1])
    generation = cursor.integer(8)
    checkpoint_digest = identity(cursor, PHYSICAL_SCHEME)
    max_tail_frames = cursor.integer(4)
    max_tail_bytes = cursor.integer(8)
    cursor.done()
    if not generation or not max_tail_frames or not max_tail_bytes:
        raise FormatError("representation CURRENT has a zero generation or budget")
    generation_dir = store / "representations" / "generations" / f"{generation:016x}"
    metadata = decode_metadata_arena(generation_dir / "metadata.arena")
    active = replay_state_journal(
        generation_dir / "state.journal",
        generation,
        checkpoint_digest,
        max_tail_frames,
        max_tail_bytes,
        metadata,
    )
    summary = validate_active_state(store, active, metadata, set(bootstrap_objects))
    summary["journal_generation"] = generation
    return summary


def decode_metadata_arena(path):
    values = {}
    nodes = {}
    contexts = (
        PROFILE_CONTEXT,
        RECORD_CONTEXT,
        MAP_CONTEXT,
        CATALOGUE_CONTEXT,
        PLACEMENT_CONTEXT,
        STATE_CONTEXT,
    )
    decoders = (
        decode_profile,
        decode_representation,
        decode_map_node,
        decode_catalogue_root,
        decode_placement_set,
        decode_representation_state,
    )
    for _, payload in frames(path, METADATA_MAGIC):
        cursor = Cursor(payload)
        kind = cursor.integer(1)
        if kind >= len(contexts):
            raise FormatError("unknown physical metadata kind")
        declared = identity(cursor, PHYSICAL_SCHEME)
        value = cursor.byte_string()
        cursor.done()
        decoders[kind](value)
        computed = physical_identity(contexts[kind], value)
        if declared != computed:
            raise FormatError("physical metadata identity mismatch")
        key = (kind, identity_bytes(declared))
        if key in values and values[key] != value:
            raise FormatError("physical metadata identity collision")
        values[key] = value
        if kind == 2:
            nodes[identity_bytes(declared)] = decode_map_node(value)
    return {"values": values, "nodes": nodes}


def metadata_value(metadata, kind, identifier):
    try:
        return metadata["values"][(kind, identity_bytes(identifier))]
    except KeyError as error:
        raise FormatError("physical metadata closure is incomplete") from error


def replay_state_journal(
    path,
    generation,
    checkpoint_digest,
    max_tail_frames,
    max_tail_bytes,
    metadata,
):
    raw = path.read_bytes()
    first = physical_frame(raw, JOURNAL_MAGIC, 0)
    if not first:
        raise FormatError("representation journal has no valid checkpoint")
    checkpoint_end = first[0]
    actual_digest = (1, 2, derive_key(JOURNAL_CONTEXT, raw[:checkpoint_end]))
    if actual_digest != checkpoint_digest:
        raise FormatError("representation checkpoint digest mismatch")
    payloads = [payload for _, payload in frames(path, JOURNAL_MAGIC)]
    if len(payloads) - 1 > max_tail_frames or len(raw) - checkpoint_end > max_tail_bytes:
        raise FormatError("representation journal exceeds CURRENT tail budget")
    cursor = Cursor(payloads[0])
    if cursor.integer(1) != 1 or cursor.integer(8) != generation:
        raise FormatError("representation journal begins with the wrong checkpoint")
    active = optional_identity(cursor, PHYSICAL_SCHEME)
    state_generation = cursor.integer(8)
    prior_digest = optional_identity(cursor, PHYSICAL_SCHEME)
    cursor.done()
    if generation != 1 or active is not None or state_generation or prior_digest is not None:
        raise FormatError("unsupported initial representation checkpoint")
    previous_state = None
    for payload in payloads[1:]:
        cursor = Cursor(payload)
        if cursor.integer(1) != 0 or cursor.integer(8) != generation:
            raise FormatError("invalid representation state CAS")
        expected = optional_identity(cursor, PHYSICAL_SCHEME)
        replacement = identity(cursor, PHYSICAL_SCHEME)
        cursor.done()
        if expected != active:
            raise FormatError("representation state CAS conflict")
        state = decode_representation_state(metadata_value(metadata, 5, replacement))
        if state["previous"] != active or state["generation"] != state_generation + 1:
            raise FormatError("representation state does not advance its predecessor")
        validate_root_generations(previous_state, state, metadata)
        active = replacement
        state_generation += 1
        previous_state = state
    if active is None:
        raise FormatError("representation journal has no active state")
    return active


def validate_root_generations(previous, current, metadata):
    catalogue = decode_catalogue_root(metadata_value(metadata, 3, current["catalogue"]))
    placements = decode_placement_set(metadata_value(metadata, 4, current["placements"]))
    if previous is None:
        if catalogue["generation"] != 1 or placements["epoch"] != 1:
            raise FormatError("initial physical roots do not start at one")
        return
    previous_catalogue = decode_catalogue_root(
        metadata_value(metadata, 3, previous["catalogue"])
    )
    previous_placements = decode_placement_set(
        metadata_value(metadata, 4, previous["placements"])
    )
    pairs = (
        (
            previous["catalogue"] == current["catalogue"],
            previous_catalogue["generation"],
            catalogue["generation"],
        ),
        (
            previous["placements"] == current["placements"],
            previous_placements["epoch"],
            placements["epoch"],
        ),
    )
    if any(now != before + (not reused) for reused, before, now in pairs):
        raise FormatError("physical root generation does not match identity change")


def validate_active_state(store, active, metadata, bootstrap_objects):
    state_bytes = metadata_value(metadata, 5, active)
    state = decode_representation_state(state_bytes)
    if physical_identity(STATE_CONTEXT, state_bytes) != active:
        raise FormatError("active representation state identity mismatch")
    catalogue_bytes = metadata_value(metadata, 3, state["catalogue"])
    catalogue = decode_catalogue_root(catalogue_bytes)
    if physical_identity(CATALOGUE_CONTEXT, catalogue_bytes) != state["catalogue"]:
        raise FormatError("active catalogue identity mismatch")
    placement_bytes = metadata_value(metadata, 4, state["placements"])
    placement_set = decode_placement_set(placement_bytes)
    if physical_identity(PLACEMENT_CONTEXT, placement_bytes) != state["placements"]:
        raise FormatError("active placement identity mismatch")

    profiles = {}
    records = {}
    placements = {}

    def profile_value(key, value):
        profile = decode_profile(value)
        if physical_identity(PROFILE_CONTEXT, value) != key:
            raise FormatError("profile leaf does not rederive its key")
        profiles[identity_bytes(key)] = profile

    def record_value(key, value):
        record = decode_representation(value)
        if physical_identity(RECORD_CONTEXT, value) != key:
            raise FormatError("representation leaf does not rederive its key")
        records[identity_bytes(key)] = record

    replica_total = 0

    def placement_value(key, value):
        nonlocal replica_total
        placement = decode_placement_entry(value)
        if placement["blob"] != key:
            raise FormatError("placement leaf does not rederive its key")
        placements[identity_bytes(key)] = placement
        replica_total += len(placement["replicas"])

    nodes = metadata["nodes"]
    validate_map(
        catalogue["profiles_root"],
        0,
        catalogue["profile_count"],
        nodes,
        profile_value,
    )
    validate_map(
        catalogue["representations_root"],
        1,
        catalogue["representation_count"],
        nodes,
        record_value,
    )
    validate_map(
        placement_set["entries_root"],
        2,
        placement_set["blob_count"],
        nodes,
        placement_value,
    )
    if replica_total != placement_set["replica_extent_count"]:
        raise FormatError("placement replica extent count mismatch")
    direct_profiles = [key for key, value in profiles.items() if value["kind"] == 0]
    if len(direct_profiles) != 1:
        raise FormatError("catalogue does not contain exactly one direct profile")
    direct_profile = (1, 2, direct_profiles[0][8:])
    validate_direct_arena(
        store,
        direct_profile,
        profiles,
        records,
        placements,
        bootstrap_objects,
    )
    return {
        "state": identity_text(active),
        "catalogue_generation": catalogue["generation"],
        "representation_count": catalogue["representation_count"],
        "placement_count": placement_set["blob_count"],
    }


def validate_direct_arena(
    store,
    direct_profile,
    profiles,
    records,
    placements,
    bootstrap_objects,
):
    arena = store / "objects.arena"
    objects = {}
    for offset, payload in frames(arena, ARENA_MAGIC):
        cursor = Cursor(payload)
        object_id = identity(cursor, LOGICAL_SCHEME)
        objects[identity_bytes(object_id)] = (offset, payload, cursor.offset)
    covered = set()
    for record in records.values():
        if identity_bytes(record["profile"]) not in profiles:
            raise FormatError("representation profile is missing")
        profile = profiles[identity_bytes(record["profile"])]
        if len(record["dependencies"]) > profile["bounds"][1]:
            raise FormatError("representation exceeds profile fanout")
        if record["maximum_reconstruction_bytes"] > profile["bounds"][3]:
            raise FormatError("representation exceeds profile output bound")
        if record["profile"] != direct_profile or record["recipe"][0] != 0:
            continue
        object_id = record["coverage"][1]
        try:
            offset, payload, canonical_offset = objects[identity_bytes(object_id)]
        except KeyError as error:
            raise FormatError("direct representation logical object is missing") from error
        canonical = payload[canonical_offset:]
        canonical_length = len(canonical)
        blob_material = identity_bytes(direct_profile) + struct.pack("<Q", len(canonical)) + canonical
        blob = physical_identity(BLOB_CONTEXT, blob_material)
        if blob != record["recipe"][1]:
            raise FormatError("direct blob does not reproduce canonical object bytes")
        placement = placements.get(identity_bytes(blob))
        if placement is None or placement["profile"] != direct_profile:
            raise FormatError("direct blob placement is missing")
        validate_direct_lengths(record, placement, canonical_length)
        expected_checksum = frame_checksum(ARENA_MAGIC, payload)
        if not any(
            node == 0
            and locator[0] == 0
            and locator[1] == 0
            and locator[2] == offset
            and locator[3] == len(payload)
            and locator[4] == expected_checksum
            for node, locator in placement["replicas"]
        ):
            raise FormatError("generation-zero placement disagrees with objects.arena")
        covered.add(identity_bytes(object_id))
    validate_direct_coverage(set(objects), covered, bootstrap_objects)


def validate_direct_lengths(record, placement, canonical_length):
    if canonical_length != record["coverage"][2]:
        raise FormatError("direct coverage length disagrees with canonical object bytes")
    if placement["encoded_length"] != canonical_length:
        raise FormatError("direct placement length disagrees with canonical object bytes")


def validate_direct_coverage(objects, covered, bootstrap_objects):
    expected = objects.difference(bootstrap_objects)
    if covered != expected:
        raise FormatError("direct catalogue does not cover every non-bootstrap arena object")
