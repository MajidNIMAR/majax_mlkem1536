"""Byte-identical publication parts must reject corruption even beside an original."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import archive_m10 as archive


class PublicationPartsTests(unittest.TestCase):
    def test_all_expected_linked_capsules_are_required(self):
        links={name:'a'*64 for name in archive.LINKS}
        archive.check_link_names(links)
        for changed in ({},dict(list(links.items())[1:]),{**links,'unrelated.json':'b'*64}):
            with self.assertRaises(ValueError):
                archive.check_link_names(changed)

    def test_measurements_must_use_the_exact_archived_source_and_builds(self):
        baseline={'source.json':b'baseline','windows/build.json':b'base-win','linux/build.json':b'base-linux'}
        qualified={'source.json':b'candidate','windows/build.json':b'new-win','linux/build.json':b'new-linux'}
        qualified['measurements/plan.json']=json.dumps({label+'_source_manifest_sha256':archive.digest(raws['source.json'])
            for label,raws in (('baseline',baseline),('candidate',qualified))}).encode()
        for label,raws in (('baseline',baseline),('candidate',qualified)):
            qualified['measurements/context/'+label+'-source.json']=raws['source.json']
            for host in ('windows','linux'):
                qualified['measurements/context/'+label+'-'+host+'-build.json']=raws[host+'/build.json']
        archive.bind_measurement_context(qualified,baseline)
        for name in ('measurements/context/baseline-source.json','measurements/context/baseline-linux-build.json',
                     'measurements/context/candidate-windows-build.json'):
            changed={**qualified,name:b'another internally consistent capture'}
            with self.subTest(name=name),self.assertRaises(ValueError):
                archive.bind_measurement_context(changed,baseline)

    def test_actual_streamed_tar_round_trip_keeps_exact_members(self):
        generated=archive.ROOT/'artifacts/generated'
        target=archive.ROOT/'target/m10-archive-tests'
        target.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='m10-archive-fixture-',dir=generated) as raw_source, \
             tempfile.TemporaryDirectory(prefix='tar-',dir=target) as raw_output:
            source,output=Path(raw_source),Path(raw_output)
            self.assertEqual(source.resolve().parent,generated.resolve())
            self.assertEqual(output.resolve().parent,target.resolve())
            (source/'nested').mkdir()
            (source/'nested/model.json').write_bytes(b'{"conditional":true}\n')
            (source/'public.bin').write_bytes(bytes(range(256)))
            record,physical=archive.write_group(output,'fixture',(source.name,))
            self.assertEqual(physical['parts'],[])
            members=archive.members(output/record['archive'])
            self.assertEqual(set(members),{'nested/model.json','public.bin'})
            self.assertEqual(archive.inventory(members),record['files'])
            self.assertEqual(members['public.bin'],bytes(range(256)))

    def test_short_and_split_bytes_are_preserved_and_corruption_rejected(self):
        parent=archive.ROOT/'target/m10-archive-tests'
        parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='bytes-',dir=parent) as temporary:
            folder=Path(temporary)
            self.assertEqual(folder.resolve().parent,parent.resolve())
            with patch.object(archive,'PART_LIMIT',16):
                writer=archive.PartWriter(folder/'short.tar.gz')
                writer.write(b'hello')
                record=writer.finish()
                self.assertEqual(record['parts'],[])
                self.assertEqual((folder/'short.tar.gz').read_bytes(),b'hello')
                raw=bytes(range(40))
                writer=archive.PartWriter(folder/'large.tar.gz')
                writer.write(raw[:13]);writer.write(raw[13:])
                record=writer.finish()
            self.assertEqual([p['bytes'] for p in record['parts']],[16,16,8])
            (folder/'provenance.json').write_text('{}')
            descriptor={'schema':'m09-byte-identical-parts-v1',
                'engine_provenance_sha256':archive.sha(folder/'provenance.json'),
                'archives':{'large.tar.gz':record}}
            (folder/'archive-parts.json').write_text(json.dumps(descriptor))
            self.assertEqual(archive.recovered_bytes(folder/'large.tar.gz'),raw)
            archive.check_parts(folder)
            (folder/'large.tar.gz').write_bytes(raw)
            (folder/record['parts'][0]['name']).write_bytes(b'x'*16)
            with self.assertRaises(ValueError):
                archive.check_parts(folder)


if __name__=='__main__':
    unittest.main()
