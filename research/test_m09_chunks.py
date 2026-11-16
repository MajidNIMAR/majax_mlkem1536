"""Preserve original archive bytes and fail closed on chunk substitutions."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from m09_chunks import ROOT, ordinary_sha, recovered_bytes, verify


class M09ChunkTests(unittest.TestCase):
    def fixture(self,folder):
        raw = b'first second'
        chunks = [b'first ',b'second']
        parts = []
        for i,data in enumerate(chunks):
            name = f'part-{i}'
            (folder/name).write_bytes(data)
            parts.append({'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        descriptor = {'schema':'m09-byte-identical-parts-v1','archives':{'whole.tar.gz':{
            'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'parts':parts}}}
        return descriptor, raw

    def temporary(self):
        parent = ROOT/'target'
        parent.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(prefix='m09-chunks-',dir=parent)

    def test_exact_join_and_corrupt_part_rejected(self):
        with self.temporary() as temporary:
            folder = Path(temporary)
            self.assertEqual(folder.resolve().parent,(ROOT/'target').resolve())
            descriptor,raw = self.fixture(folder)
            (folder/'archive-parts.json').write_text(json.dumps(descriptor))
            self.assertEqual(recovered_bytes(folder/'whole.tar.gz'),raw)
            (folder/'part-1').write_bytes(b'second!')
            with self.assertRaises(ValueError):
                recovered_bytes(folder/'whole.tar.gz')

    def test_rehashed_part_cannot_change_original_identity(self):
        with self.temporary() as temporary:
            folder = Path(temporary)
            descriptor,_ = self.fixture(folder)
            (folder/'part-1').write_bytes(b'xxxxxx')
            descriptor['archives']['whole.tar.gz']['parts'][1]['sha256']=hashlib.sha256(b'xxxxxx').hexdigest()
            (folder/'archive-parts.json').write_text(json.dumps(descriptor))
            with self.assertRaisesRegex(ValueError,'joined archive differs'):
                recovered_bytes(folder/'whole.tar.gz')

    def test_alias_and_escape_rejected(self):
        with self.temporary() as temporary:
            folder = Path(temporary)
            descriptor,_ = self.fixture(folder)
            for bad in ('../part-0','C:/part-0','part-0'):
                descriptor['archives']['whole.tar.gz']['parts'][1]['name']=bad
                (folder/'archive-parts.json').write_text(json.dumps(descriptor))
                with self.subTest(bad=bad),self.assertRaises(ValueError):
                    recovered_bytes(folder/'whole.tar.gz')

    def test_complete_original_cannot_hide_missing_or_corrupt_parts(self):
        with self.temporary() as temporary:
            root = Path(temporary)
            capsule = root/'results/engine/m09-001'
            controls = root/'results/engine/m09-chunks-001'
            capsule.mkdir(parents=True)
            controls.mkdir()
            descriptor,raw = self.fixture(capsule)
            (capsule/'whole.tar.gz').write_bytes(raw)
            checksum = hashlib.sha256(raw).hexdigest()
            engine = {'groups':{'rejected':{'archive':'whole.tar.gz','archive_sha256':checksum}}}
            (capsule/'provenance.json').write_text(json.dumps(engine))
            engine_sha = ordinary_sha(capsule/'provenance.json')
            descriptor['engine_provenance_sha256'] = engine_sha
            for folder in (capsule,controls):
                (folder/'archive-parts.json').write_text(json.dumps(descriptor))
            receipt = {'schema':'m09-chunk-controls-v1','scientific_payload_bytes_changed':False,'new_acquisitions':0,
                'engine_provenance_sha256':engine_sha,
                'output_sha256':{'archive-parts.json':ordinary_sha(controls/'archive-parts.json')}}
            (controls/'provenance.json').write_text(json.dumps(receipt))
            with patch('m09_chunks.ROOT',root):
                verify(capsule)
                (capsule/'part-1').write_bytes(b'xxxxxx')
                with self.assertRaisesRegex(ValueError,'chunk bytes differ'):
                    verify(capsule)


if __name__=='__main__':
    unittest.main()
