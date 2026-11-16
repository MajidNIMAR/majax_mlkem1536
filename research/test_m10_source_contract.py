"""Fault-oriented checks on the live M10 source, not compiled CT/erasure tests."""
import hashlib
import json
import re
import tarfile
import unittest

from verify_r1_certificate_bridge import ROOT, verify_static_contract
from m09_chunks import open_archive, sha


class M10SourceContractTests(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / "crates/kem1536/src/dev_kem.rs").read_text("utf-8-sig")
        self.flat = re.sub(r"\s+", "", self.source)

    def reject(self, before, after, site=0):
        positions = [m.start() for m in re.finditer(re.escape(before), self.flat)]
        self.assertGreater(len(positions), site, before)
        at = positions[site]
        mutated = self.flat[:at] + after + self.flat[at + len(before):]
        with self.subTest(fragment=before, site=site), self.assertRaisesRegex(
                ValueError, "reviewed R1 source contract changed"):
            verify_static_contract(mutated)

    def test_live_m10_is_an_additive_realization_not_a_formal_proof(self):
        result = verify_static_contract(self.source)
        self.assertEqual(result["realization"], "M10-borrowed-XOF-copied-output-3")
        self.assertEqual(result["reviewed_source_anchors"], 78)
        self.assertFalse(result["formal_program_verification"])

    def frozen_source(self, version, source_sha):
        capsule = ROOT / "results/engine/m10-001"
        if (capsule / "provenance.json").is_file():
            record = json.loads((capsule / "provenance.json").read_text("utf-8"))["groups"]["rejected"]
            archive_path = capsule / record["archive"]
            self.assertEqual(sha(archive_path), record["archive_sha256"])
            member = "m10-final-" + version + "/source/crates/kem1536/src/dev_kem.rs"
            raw = None
            with open_archive(archive_path) as stream, tarfile.open(fileobj=stream, mode="r|gz") as archive:
                for entry in archive:
                    if entry.name == member:
                        raw = archive.extractfile(entry).read()
                        break
            self.assertIsNotNone(raw, "immutable source fixture absent from capsule")
            self.assertEqual(hashlib.sha256(raw).hexdigest(), record["files"][member]["sha256"])
        else:
            # Before the new capsule is sealed, the explicitly hashed capture
            # supplies the same immutable fixture. Public CI must use the archive.
            raw = (ROOT / ("artifacts/generated/m10-final-" + version + "/source/crates/kem1536/src/dev_kem.rs")).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), source_sha)
        return raw.decode("utf-8-sig")

    def test_frozen_first_variant_keeps_its_75_anchors_and_selection_guards(self):
        source = self.frozen_source("001", "04495b32ebb41fa52e4a919906cee585667a314d28bf35747b05697f4858ed2e")
        result = verify_static_contract(source)
        self.assertEqual((result["realization"], result["reviewed_source_anchors"]),
                         ("M10-destination-derived-conditional-assignment-1", 75))
        self.assertFalse(result["formal_program_verification"])
        self.assertIn("out.ct_assign(good, valid);", source)
        with self.assertRaises(ValueError):
            verify_static_contract(source.replace("out.ct_assign(good, valid);", "out.ct_assign(good, !valid);", 1))

    def test_frozen_second_variant_keeps_its_77_anchors_and_borrowed_xof(self):
        source = self.frozen_source("002", "d53923d79a74664acc2247dc192489ac04b825f597d6ffd25eb05d1d0de4cfac")
        result = verify_static_contract(source)
        self.assertEqual((result["realization"], result["reviewed_source_anchors"]),
                         ("M10-borrowed-XOF-destination-assignment-2", 77))
        self.assertFalse(result["formal_program_verification"])
        self.assertIn("h.finalize_xof_reset().read(&mut out[..]);", source)
        with self.assertRaises(ValueError):
            verify_static_contract(source.replace("h.finalize_xof_reset().read(&mut out[..]);",
                                                  "h.finalize_xof().read(&mut out[..]);", 1))

    def test_primitive_framing_and_destinations_reject_regressions(self):
        for before, after in (
            ("Sha3_512::new()", "Sha3_256::new()"),
            ("Shake256::default()", "Shake128::default()"),
            ("Digest::update(&muth,TAG);", ""),
            ('Digest::update(&muth,b"H\\0");', 'Digest::update(&muth,b"G\\0");'),
            ("Digest::update(&muth,label);", ""),
            ("forpinparts{Digest::update(&muth,p);}", ""),
            ("h.update(TAG);h.update(label);", "h.update(label);h.update(TAG);"),
            ("forpinparts{h.update(p);}", ""),
            ("Digest::finalize_into_reset(&muth,out.into());", "h.finalize();"),
            ("h.finalize_xof_reset().read(&mutout[..]);", "h.finalize_xof_reset().read(&mutout[1..]);"),
            ('xof_into(b"N\\0",&[seed,&[nonce]],&mutbytes)',
             'xof_into(b"N\\0",&[seed,&[nonce+1]],&mutbytes)'),
            ('derive_into(b"KG\\0",&[d,&[6]],&mutexpanded)',
             'derive_into(b"KG\\0",&[d,&[5]],&mutexpanded)'),
            ('derive_into(b"G\\0",&[m,&hash_public(ek.as_bytes())],&mutmaterial)',
             'derive_into(b"G\\0",&[m,&hash_public(ek.as_bytes())],&mutother)'),
            ('derive_into(b"G\\0",&[&m[..],&dk.0[offset..offset+32]],&mutmaterial)',
             'derive_into(b"G\\0",&[&m[..],&dk.0[offset+1..offset+33]],&mutmaterial)'),
            ("letmutbytes=Zeroizing::new([0;192]);", "letmutbytes=Zeroizing::new([0;191]);"),
            ("letmutexpanded=Zeroizing::new([0;64]);", "letmutexpanded=[0;64];"),
        ):
            self.reject(before, after)

    def test_secret_xof_cannot_revert_to_consuming_finalization_under_reset_identity(self):
        self.reject("use shake::digest::ExtendableOutputReset;".replace(" ", ""), "")
        self.reject("h.finalize_xof_reset().read(&mutout[..]);", "h.finalize_xof().read(&mutout[..]);")

    def test_local_selection_owner_is_copied_to_output_and_keeps_its_drop(self):
        self.reject("SharedSecret(Zeroizing::new(*key))", "SharedSecret(key)")

    def test_filled_return_helpers_stay_out_of_default_api_build(self):
        before = '#[cfg(any(test,feature="research-vectors"))]'
        # The first two occurrences are exactly the reviewed derive/xof wrappers.
        for site in (0, 1):
            self.reject(before, "", site)

    def test_rejection_selection_direction_mask_and_owner_are_bound(self):
        for before, after in (
            ("usectutils::{Choice,CtAssign,CtEq};", "usectutils::{Choice,CtSelect,CtEq};"),
            ("out.ct_assign(good,valid);", "out.ct_assign(good,!valid);"),
            ("#[inline(never)]fnassign_shared_secret_into", "fnassign_shared_secret_into"),
            ('xof_into(b"J\\0",&[&dk.0[offset+32..],c.as_bytes()],&mutkey)',
             'xof_into(b"J\\0",&[&dk.0[offset..offset+32],c.as_bytes()],&mutkey)'),
            ("assign_shared_secret_into(&mutkey,", "assign_shared_secret_into(&mutother,"),
            ('material[..32].try_into().expect("fixedfavourablekeyview")',
             'material[32..].try_into().expect("fixedfavourablekeyview")'),
            ("c.as_bytes().ct_eq(&cp[..]),", "cp.as_slice().ct_eq(&cp[..]),"),
            ("c.as_bytes().ct_eq(&cp[..]),", "!c.as_bytes().ct_eq(&cp[..]),"),
            ("SharedSecret(Zeroizing::new(*key))", "SharedSecret(Zeroizing::new([0;32]))"),
        ):
            self.reject(before, after)

    def test_m09_noise_entropy_and_message_guards_still_apply_to_live_m10(self):
        for before, after in (
            ("structKeygenNoise<'a>(&'a[u8;32]);", "structKeygenNoise<'a>(&'a[u8]);"),
            ("material[32..].try_into()", "material[..32].try_into()"),
            ("assert!(row<RANK,", "assert!(row<=RANK,"),
            ("offset+rowasu8", "offset+1+rowasu8"),
            ("noise_into(self.0,row_nonce(row,0),out)", "noise_into(self.0,row_nonce(row,1),out)"),
            ("noise_into(self.0,row_nonce(row,RANKasu8),out)", "noise_into(self.0,row_nonce(row,5),out)"),
            ("noise_into(self.0,(2*RANK)asu8,out)", "noise_into(self.0,11,out)"),
            ("bit(6*j+2)", "bit(6*j+3)"),
            ("m.fill(0);", ""),
            ("bytes.zeroize();returnErr(error);", "returnErr(error);"),
            ("fill_entropy_into(&mutseeds,fill)?;", ""),
            ("fill_entropy_into(&mutm,fill)?;", ""),
            ("pke_decrypt_into(&dk.0[..VECTOR_BYTES],c,&mutm);", ""),
            ("pke_encrypt_into(ek,&m,&EncryptionCoins(seed_tail(&material)),&mutcp);", ""),
            ("Q/2", "Q/2+1"),
        ):
            self.reject(before, after)

    def test_streamed_pke_arithmetic_and_import_validation_remain_bound(self):
        for before, after in (
            ("uniform(rho,iasu8,jasu8)", "uniform(rho,jasu8,iasu8)"),
            ("uniform(rho,jasu8,iasu8)", "uniform(rho,iasu8,jasu8)"),
            ("message_poly_into(m,&mutproduct)", "message_poly_into(m,&mutcoefficient)"),
            ("v.subtract_assign(&secret)", "v.add_assign(&secret)"),
            ("&sk[i*POLY_BYTES..(i+1)*POLY_BYTES]", "&sk[..POLY_BYTES]"),
            ("&c.0[i*POLY_BYTES..(i+1)*POLY_BYTES]", "&c.0[..POLY_BYTES]"),
            ("pack_into(product.coefficients(),5,&mutout[VECTOR_BYTES..])",
             "pack_into(product.coefficients(),4,&mutout[VECTOR_BYTES..])"),
            ("forgroupinbytes.chunks_exact(13){", "forgroupinbytes.chunks_exact(13).take(1){"),
            ("ifnoncanonical!=0{returnErr(Error::NoncanonicalEncoding);}", ""),
        ):
            self.reject(before, after)
        for before, after, count in (
            ("sum.clear();", "", 3),
            ("sum.inverse_into(&mutproduct);", "sum.clear();", 3),
            ("coefficient.add_assign(&product);", "coefficient.subtract_assign(&product);", 4),
            ("validate_vector_encoding(&bytes[..VECTOR_BYTES])?;", "", 2),
            ("noncanonical|=noncanonical_13(", "noncanonical=noncanonical_13(", 8),
        ):
            self.assertEqual(self.flat.count(before), count, before)
            for site in range(count):
                self.reject(before, after, site)


if __name__ == "__main__":
    unittest.main()
