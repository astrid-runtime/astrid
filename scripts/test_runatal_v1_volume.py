#!/usr/bin/env python3
"""Independent hosted-volume page grammar and recovery regressions."""
import struct
import tempfile
import unittest
from pathlib import Path

from runatal_v1_volume import VolumeFormatError, recover_volume
from runatal_v1_blake3 import derive_key

def fixture(page_mutation=None, reference_mutation=None):
    data=bytearray(b'ASTVOL1\0'); sequence=0
    def append(operation,name,logical,payload):
        nonlocal sequence
        sequence+=1;name=name.encode();offset=len(data)
        material=struct.pack('<QB H Q Q',sequence,operation,len(name),logical,len(payload))+name+payload
        checksum=derive_key('astrid volume record v1',material)
        header=b'ASTREG1\0'+struct.pack('<QQBHQQ',75+len(name)+len(payload),sequence,operation,len(name),logical,len(payload))+checksum
        assert len(header)==75
        data.extend(header+name+payload)
        return offset,offset+75+len(name),sequence,checksum
    name='data/test';value=b'acknowledged'
    append(1,name,0,b'')
    _,physical,_,_=append(2,name,0,value)
    append(8,'system/volume-commit',0,b'')
    page=b'ASTXPG1\0'+struct.pack('<B3xH2x',0,1)+struct.pack('<QQQ',0,len(value),physical)
    page=page.ljust(4096,b'\0')
    if page_mutation is not None: page=page_mutation(page)
    offset,_,seq,checksum=append(9,'system/volume-extent-index',0,page)
    reference=struct.pack('<QQ',offset,seq)+checksum+struct.pack('<QQQB7x',0,len(value),1,0)
    if reference_mutation is not None: reference=reference_mutation(reference)
    assert len(reference)==80
    catalogue=b'ASTMAP2\0'+struct.pack('<IH',1,len(name))+name.encode()+struct.pack('<QB',len(value),1)+reference
    append(8,'system/volume-commit',0,catalogue)
    return data,{name:value}


def replace_bytes(data, offset, value):
    return data[:offset] + value + data[offset + len(value):]


class IndependentReaderPagedRegression(unittest.TestCase):
    def recover(self, data):
        with tempfile.TemporaryDirectory(prefix="astrid-independent-volume-") as directory:
            path = Path(directory) / "astrid.volume"
            path.write_bytes(data)
            before = path.read_bytes()
            try:
                return recover_volume(path)
            finally:
                self.assertEqual(path.read_bytes(), before, "offline reader mutated source")

    def test_valid_paged_checkpoint_recovers_public_region(self):
        data, expected = fixture()
        self.assertEqual(self.recover(data), expected)

    def test_checksum_valid_malformed_page_is_rejected(self):
        for offset, replacement in [(0, b"!"), (9, b"!"), (14, b"!"), (4095, b"!"), (12, bytes(2))]:
            with self.subTest(offset=offset):
                data, _ = fixture(page_mutation=lambda page: replace_bytes(page, offset, replacement))
                with self.assertRaises(VolumeFormatError):
                    self.recover(data)

    def test_checksum_valid_forged_root_is_rejected(self):
        for offset, replacement in [(16, bytes(32)), (64, struct.pack("<Q", 2)), (73, b"!")]:
            with self.subTest(offset=offset):
                data, _ = fixture(reference_mutation=lambda ref: replace_bytes(ref, offset, replacement))
                with self.assertRaises(VolumeFormatError):
                    self.recover(data)

    def test_forward_payload_reference_is_rejected(self):
        data, _ = fixture(page_mutation=lambda page: replace_bytes(page, 32, struct.pack("<Q", (1 << 64) - 1)))
        with self.assertRaisesRegex(VolumeFormatError, "payload bounds"):
            self.recover(data)

    def test_root_record_must_complete_before_commit(self):
        data, _ = fixture(reference_mutation=lambda ref: replace_bytes(ref, 0, struct.pack("<Q", int.from_bytes(ref[:8], "little") + 1)))
        with self.assertRaisesRegex(VolumeFormatError, "precede parent"):
            self.recover(data)

    def test_unpublished_complete_page_preserves_prior_acknowledged_namespace(self):
        data, expected = fixture()
        # Remove only the final commit; complete index pages are unpublished.
        final = data.rfind(b"ASTREG1\0")
        self.assertEqual(self.recover(data[:final]), expected)


if __name__ == "__main__":
    unittest.main()
