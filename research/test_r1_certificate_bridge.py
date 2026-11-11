"""Fault-oriented checks for the independent R1 correctness bridge."""

from collections import Counter
from copy import deepcopy
from fractions import Fraction
import hashlib
import itertools
import json
import re
import tarfile
import unittest

from verify_r1_certificate_bridge import (ROOT, Q, cbd_bits, compress, decompress,
                                          multiply, quantizer_contract, verify_certificate,
                                          verify_static_contract, verify_vector)


class CertificateBridgeTests(unittest.TestCase):
    def frozen_source(self, milestone):
        relative = "crates/kem1536/src/dev_kem.rs"
        folder = ROOT / "results/engine" / {
            "M02": "hardening-001", "M04": "m04-001", "M06": "m06-001", "M07": "m07-001",
        }[milestone]
        manifest = json.loads((folder / "provenance.json").read_text("utf-8"))
        if milestone == "M07":
            member = "candidate-source/" + relative
            with tarfile.open(folder / "measurements.tar.gz") as archive:
                raw = archive.extractfile(member).read()
            checksum = manifest["stages"]["measurements"]["files"][member]["sha256"]
        elif milestone == "M04":
            with tarfile.open(folder / "sources.tar.gz") as archive:
                raw = archive.extractfile(relative).read()
            checksum = manifest["source_sha256"][relative]
        else:
            path = folder / "sources" / relative
            raw = path.read_bytes()
            checksum = (manifest["input_sha256"][path.relative_to(ROOT).as_posix()]
                        if milestone == "M02" else
                        manifest["output_sha256"]["sources/" + relative])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), checksum,
                         f"{milestone} frozen source fixture changed")
        return raw.decode("utf-8")

    def assert_contract_mutation_rejected(self, flat, before, after, occurrence=0):
        positions = [match.start() for match in re.finditer(re.escape(before), flat)]
        self.assertGreater(len(positions), occurrence, before)
        at = positions[occurrence]
        mutant = flat[:at] + after + flat[at + len(before):]
        with self.subTest(mutation=before, site=occurrence), self.assertRaisesRegex(
                ValueError, "reviewed R1 source contract changed"):
            verify_static_contract(mutant)

    def test_frozen_source_realizations_and_anchor_counts_are_retained(self):
        for milestone, realization, count in (
            ("M02", "M02-schoolbook-return-owned-1", 21),
            ("M04", "M04-destination-owned-NTT-scalar-1", 24),
            ("M06", "M06-destination-owned-NTT-accumulated-1", 31),
            ("M07", "M07-destination-owned-NTT-streamed-1", 35),
        ):
            with self.subTest(milestone=milestone):
                contract = verify_static_contract(self.frozen_source(milestone))
                self.assertEqual(contract["realization"], realization)
                self.assertEqual(contract["reviewed_source_anchors"], count)
                self.assertFalse(contract["formal_program_verification"])

    def test_bits_cbd_all_64_patterns_and_disjoint_word_slices(self):
        words = [cbd_bits(i) for i in range(64)]
        self.assertEqual(Counter(words), {-3: 1, -2: 6, -1: 15, 0: 20, 1: 15, 2: 6, 3: 1})
        # Joint law of two disjoint six-bit coefficients is exactly a product.
        joint = Counter((cbd_bits(word & 63), cbd_bits(word >> 6)) for word in range(4096))
        for a, na in Counter(words).items():
            for b, nb in Counter(words).items():
                self.assertEqual(joint[a, b], na * nb)

    def test_decoder_support_and_first_unsafe_upper_boundary(self):
        result = quantizer_contract()
        self.assertEqual(result["decoder_intervals"], [[-1920, 1920], [-1920, 1919]])
        self.assertEqual(result["common_safe_radius"], 1799)
        self.assertEqual(result["v_error_range"], [-120, 120])
        self.assertEqual(compress((decompress(1, 1) + 1799 + 120) % Q, 1), 1)
        self.assertEqual(compress((decompress(1, 1) + 1800 + 120) % Q, 1), 0)

    def test_exact_certificate_and_tampering_rejected(self):
        saved = json.loads((ROOT / "results/j2/run-004/correctness-certificate.json").read_text())
        result = verify_certificate(saved)
        self.assertTrue(result["exact_upper_at_most_2_pow_minus_310"])
        for field, value in (("common_safe_radius", 1800), ("one_sided_tail_threshold", 1801),
                             ("tilt_z", "14/10"), ("v_error_range", [-119, 120])):
            bad = deepcopy(saved)
            bad[field] = value
            with self.assertRaises(ValueError):
                verify_certificate(bad)
        bad = deepcopy(saved)
        bad["mgf_product"]["numerator_hex"] = "1"
        with self.assertRaises(ValueError):
            verify_certificate(bad)

    def test_negacyclic_sign_and_transpose_cancellation_exhaustive_small_ring(self):
        n = 3
        # Basis products exhaust all reductions X^i X^j including wrap signs.
        for i, j in itertools.product(range(n), repeat=2):
            a, b, expected = [0] * n, [0] * n, [0] * n
            a[i], b[j] = 1, 1
            expected[(i + j) % n] = -1 if i + j >= n else 1
            self.assertEqual(multiply(a, b), expected)
        # The ring is commutative; expand every matrix/s/r basis triple.
        for ai, sj, rj in itertools.product(range(n), repeat=3):
            a, s, r = [0] * n, [0] * n, [0] * n
            a[ai], s[sj], r[rj] = 1, 1, 1
            self.assertEqual(multiply(multiply(a, s), r), multiply(s, multiply(a, r)))

    def test_shared_secret_wrong_ideal_independence_not_assumed(self):
        # s reused in both terms: (s*a)+(s*b) has a different MGF from
        # two independent products. This catches invalid blanket independence.
        samples = (-1, 0, 0, 1)
        z = Fraction(13, 10)
        shared = sum((z ** (s * a + s * b) for s, a, b in itertools.product(samples, repeat=3)), Fraction()) / 64
        independent = (sum((z ** (s * a) for s, a in itertools.product(samples, repeat=2)), Fraction()) / 16) ** 2
        self.assertNotEqual(shared, independent)

    def test_source_contract_rejects_sampler_and_rounding_regression(self):
        source = (ROOT / "crates/kem1536/src/dev_kem.rs").read_text()
        verify_static_contract(source)
        call = "noise_into(seed, 12" if "fn noise_into(" in source else "noise(seed, 12"
        for before, after in (("xof::<192>", "xof::<191>"),
                              (call, call.replace("12", "11")),
                              ("Q / 2", "Q / 2 + 1")):
            self.assertIn(before, source)
            with self.assertRaises(ValueError):
                verify_static_contract(source.replace(before, after))

    def test_synthetic_vector_reconstruction_and_bit_flip(self):
        import gzip
        with gzip.open(ROOT / "results/engine/r1-001/vectors.jsonl.gz", "rt") as stream:
            row = json.loads(next(stream))
        result = verify_vector(row)
        self.assertEqual(result["coefficients_checked"], 256)
        bad = deepcopy(row)
        bad["ek"][0] ^= 1
        with self.assertRaisesRegex(ValueError, "honest-key"):
            verify_vector(bad)

    def test_accumulated_ntt_contract_rejects_wrong_transpose_and_stale_sum(self):
        source = self.frozen_source("M06")
        self.assertEqual(verify_static_contract(source)["realization"],
                         "M06-destination-owned-NTT-accumulated-1")
        for before, after in (("uniform(rho, j as u8, i as u8)", "uniform(rho, i as u8, j as u8)"),
                              ("sum.clear();", "// missing reset"),
                              ("v.subtract_assign(&product)", "v.add_assign(&product)"),
                              ("sum.multiply_add_assign(&left, &right)", "sum.clear()"),
                              ("randomness.forward_into(transformed)", "transformed.clear()")):
            self.assertIn(before, source)
            with self.subTest(mutation=before), self.assertRaises(ValueError):
                verify_static_contract(source.replace(before, after))
        for occurrence in (0, 1):
            for before, after in (("sum.inverse_into(&mut product);", "sum.clear();"),
                                  ("value.add_assign(&product);", "value.subtract_assign(&product);")):
                at = source.index(before)
                if occurrence:
                    at = source.index(before, at + len(before))
                mutant = source[:at] + after + source[at + len(before):]
                with self.subTest(site=occurrence, mutation=before), self.assertRaises(ValueError):
                    verify_static_contract(mutant)
        with self.assertRaises(ValueError):
            verify_static_contract(source.replace("encode_vector_into(&t,", "encode_vector_into(&s,", 1))

    def test_streamed_contract_rejects_decode_scan_and_import_faults(self):
        source = self.frozen_source("M07")
        self.assertEqual(verify_static_contract(source)["realization"],
                         "M07-destination-owned-NTT-streamed-1")
        flat = re.sub(r"\s+", "", source)
        for before, after in (
            ("constVECTOR_BYTES:usize=RANK*POLY_BYTES;",
             "constVECTOR_BYTES:usize=(RANK-1)*POLY_BYTES;"),
            ("debug_assert_eq!(bytes.len(),POLY_BYTES);", ""),
            ("unpack_coefficient(bytes,13,j)", "unpack_coefficient(bytes,12,j)"),
            ("noncanonical|=((u32::from(v).wrapping_sub(u32::from(Q))>>31)^1)asu16;",
             "noncanonical|=0;"),
            ("reduce_once(u32::from(v))", "v"),
            ("ifbytes.len()!=VECTOR_BYTES", "ifbytes.len()<VECTOR_BYTES"),
            ("forrowinbytes.chunks_exact(POLY_BYTES){",
             "forrowinbytes.chunks_exact(POLY_BYTES).take(1){"),
            ("noncanonical|=decode_polynomial_into(row,&mutchecked);",
             "noncanonical=decode_polynomial_into(row,&mutchecked);"),
            ("ifnoncanonical!=0{returnErr(Error::NoncanonicalEncoding);}", ""),
            ("validate_vector_encoding(&ek[..VECTOR_BYTES])?;", ""),
            ("letek=&bytes[VECTOR_BYTES..VECTOR_BYTES+PUBLIC_KEY_BYTES];",
             "letek=&bytes[VECTOR_BYTES+1..VECTOR_BYTES+PUBLIC_KEY_BYTES];"),
            ("hash_public(ek).as_slice().ct_eq(&bytes[offset..offset+32])",
             "hash_public(ek).as_slice().ct_eq(&bytes[offset+1..offset+33])"),
        ):
            self.assert_contract_mutation_rejected(flat, before, after)
        # Both imported vectors are scanned; neither predicate may be omitted.
        before = "validate_vector_encoding(&bytes[..VECTOR_BYTES])?;"
        self.assertEqual(flat.count(before), 2)
        for site in range(2):
            self.assert_contract_mutation_rejected(flat, before, "", site)

    def test_direct_import_contract_checks_each_encoded_group_component(self):
        source = (ROOT / "crates/kem1536/src/dev_kem.rs").read_text(encoding="utf-8")
        contract = verify_static_contract(source)
        self.assertEqual(contract["realization"], "M08-direct-encoding-NTT-streamed-1")
        self.assertEqual(contract["reviewed_source_anchors"], 36)
        self.assertFalse(contract["formal_program_verification"])
        flat = re.sub(r"\s+", "", source)
        for before, after in (
            ("#[inline(always)]fnnoncanonical_13(value:u16)->u16", "fnnoncanonical_13(value:u16)->u16"),
            ("u32::from(value).wrapping_sub(u32::from(Q))", "u32::from(value).wrapping_sub(u32::from(Q-1))"),
            ("forgroupinbytes.chunks_exact(13){", "forgroupinbytes.chunks_exact(13).take(1){"),
            ("bytes.chunks_exact(13)", "bytes.chunks_exact(12)"),
            ("letb=|i:usize|u16::from(group[i]);", "letb=|i:usize|u16::from(group[i%12]);"),
            ("b(0)|((b(1)&31)<<8)", "b(0)|((b(1)&63)<<8)"),
            ("(b(1)>>5)|(b(2)<<3)|((b(3)&3)<<11)", "(b(1)>>4)|(b(2)<<3)|((b(3)&3)<<11)"),
            ("(b(3)>>2)|((b(4)&127)<<6)", "(b(3)>>2)|((b(4)&63)<<6)"),
            ("(b(4)>>7)|(b(5)<<1)|((b(6)&15)<<9)", "(b(4)>>7)|(b(5)<<1)|((b(6)&15)<<8)"),
            ("(b(6)>>4)|(b(7)<<4)|((b(8)&1)<<12)", "(b(6)>>4)|(b(7)<<4)|((b(8)&1)<<11)"),
            ("(b(8)>>1)|((b(9)&63)<<7)", "(b(8)>>1)|((b(9)&31)<<7)"),
            ("(b(9)>>6)|(b(10)<<2)|((b(11)&7)<<10)", "(b(9)>>6)|(b(10)<<2)|((b(11)&7)<<9)"),
            ("(b(11)>>3)|(b(12)<<5)", "(b(11)>>3)|(b(12)<<4)"),
            ("ifbytes.len()!=VECTOR_BYTES", "ifbytes.len()<VECTOR_BYTES"),
            ("ifnoncanonical!=0{returnErr(Error::NoncanonicalEncoding);}", ""),
            ("validate_vector_encoding(&ek[..VECTOR_BYTES])?;", ""),
            ("letek=&bytes[VECTOR_BYTES..VECTOR_BYTES+PUBLIC_KEY_BYTES];", "letek=&bytes[VECTOR_BYTES+1..VECTOR_BYTES+PUBLIC_KEY_BYTES];"),
            ("hash_public(ek).as_slice().ct_eq(&bytes[offset..offset+32])", "hash_public(ek).as_slice().ct_eq(&bytes[offset+1..offset+33])"),
            ("unpack_coefficient(bytes,13,j)", "unpack_coefficient(bytes,12,j)"),
            ("reduce_once(u32::from(v))", "v"),
        ):
            self.assert_contract_mutation_rejected(flat, before, after)
        before = "noncanonical|=noncanonical_13("
        self.assertEqual(flat.count(before), 8)
        for site in range(8):
            self.assert_contract_mutation_rejected(flat, before, "noncanonical=noncanonical_13(", site)
        for site in range(2):
            self.assert_contract_mutation_rejected(flat, "validate_vector_encoding(&bytes[..VECTOR_BYTES])?;", "", site)

    def test_direct_import_contract_rejects_early_success_and_legacy_fallback(self):
        source = (ROOT / "crates/kem1536/src/dev_kem.rs").read_text(encoding="utf-8")
        flat = re.sub(r"\s+", "", source)
        before = "ifnoncanonical!=0{returnErr(Error::NoncanonicalEncoding);}Ok(())"
        self.assert_contract_mutation_rejected(flat, before, "returnOk(());" + before)
        helper = "#[inline(always)]fnnoncanonical_13(value:u16)->u16{((u32::from(value).wrapping_sub(u32::from(Q))>>31)^1)asu16}"
        self.assertIn(helper, flat)
        with self.assertRaisesRegex(ValueError, "reviewed R1 source contract changed"):
            verify_static_contract(flat.replace(helper, "", 1))

    def test_streamed_contract_rejects_sampler_orientation_and_row_packing_faults(self):
        source = (ROOT / "crates/kem1536/src/dev_kem.rs").read_text()
        verify_static_contract(source)
        flat = re.sub(r"\s+", "", source)
        for before, after in (
            ("debug_assert_eq!(encoded_s.len(),VECTOR_BYTES);", ""),
            ("noise_into(sigma,iasu8,&mutcoefficient)",
             "noise_into(sigma,1+iasu8,&mutcoefficient)"),
            ("noise_into(sigma,6+iasu8,&mutcoefficient)",
             "noise_into(sigma,5+iasu8,&mutcoefficient)"),
            ("noise_into(seed,iasu8,&mutcoefficient)",
             "noise_into(seed,1+iasu8,&mutcoefficient)"),
            ("noise_into(seed,6+iasu8,&mutcoefficient)",
             "noise_into(seed,5+iasu8,&mutcoefficient)"),
            ("noise_into(seed,12,&mutcoefficient)",
             "noise_into(seed,11,&mutcoefficient)"),
            ("uniform(rho,iasu8,jasu8)", "uniform(rho,jasu8,iasu8)"),
            ("uniform(rho,jasu8,iasu8)", "uniform(rho,iasu8,jasu8)"),
            ("&mutencoded_s[i*POLY_BYTES..(i+1)*POLY_BYTES]", "&mutencoded_s[..POLY_BYTES]"),
            ("&mutek[i*POLY_BYTES..(i+1)*POLY_BYTES]", "&mutek[..POLY_BYTES]"),
            ("&mutout[i*POLY_BYTES..(i+1)*POLY_BYTES]", "&mutout[..POLY_BYTES]"),
            ("pack_into(coefficient.coefficients(),13,&mutencoded_s[",
             "pack_into(coefficient.coefficients(),12,&mutencoded_s["),
            ("pack_into(coefficient.coefficients(),13,&mutek[",
             "pack_into(coefficient.coefficients(),12,&mutek["),
            ("pack_into(coefficient.coefficients(),13,&mutout[",
             "pack_into(coefficient.coefficients(),12,&mutout["),
            ("pke_keygen_into(d,&mutsk[..VECTOR_BYTES])",
             "pke_keygen_into(d,&mutsk[32..VECTOR_BYTES])"),
            ("letmutsk=SecretBox::zero();letek=pke_keygen_into(d,&mutsk[..VECTOR_BYTES]);",
             "letmutsk=SecretBox::zero();letek=pke_keygen_into(z,&mutsk[..VECTOR_BYTES]);"),
            ("letmutsk=SecretBox::zero();letek=pke_keygen_into(d,&mutsk[..VECTOR_BYTES]);",
             "letmutencoded_s=Zeroizing::new([0;VECTOR_BYTES]);"
             "letek=pke_keygen_into(d,&mutencoded_s[..]);letmutsk=SecretBox::zero();"
             "sk[..VECTOR_BYTES].copy_from_slice(&encoded_s[..]);"),
            ("&ek[i*POLY_BYTES..(i+1)*POLY_BYTES]", "&ek[..POLY_BYTES]"),
            ("&sk[i*POLY_BYTES..(i+1)*POLY_BYTES]", "&sk[..POLY_BYTES]"),
            ("&c.0[i*POLY_BYTES..(i+1)*POLY_BYTES]", "&c.0[..POLY_BYTES]"),
            ("message_poly_into(m,&mutproduct)", "message_poly_into(m,&mutcoefficient)"),
            ("compress(coefficient.coefficients()[i],5)", "compress(coefficient.coefficients()[i],4)"),
            ("pack_into(product.coefficients(),5,&mutout[VECTOR_BYTES..])",
             "pack_into(coefficient.coefficients(),5,&mutout[VECTOR_BYTES..])"),
            ("&mutout[VECTOR_BYTES..]", "&mutout[VECTOR_BYTES-1..]"),
            ("v.subtract_assign(&secret)", "v.add_assign(&secret)"),
        ):
            self.assert_contract_mutation_rejected(flat, before, after)
        # Reject a partial loop at each distinct streamed dot-product site.
        before = "foriin0..RANK{"
        self.assertEqual(flat.count(before), 3)
        for site in range(3):
            self.assert_contract_mutation_rejected(flat, before, "foriin0..RANK-1{", site)

    def test_streamed_contract_checks_every_reset_inverse_accumulation_and_addition_site(self):
        source = (ROOT / "crates/kem1536/src/dev_kem.rs").read_text()
        verify_static_contract(source)
        flat = re.sub(r"\s+", "", source)
        for before, after, count in (
            ("sum.clear();", "", 3),
            ("sum.inverse_into(&mutproduct);", "sum.clear();", 3),
            ("coefficient.add_assign(&product);", "coefficient.subtract_assign(&product);", 4),
            ("sum.multiply_add_assign(&matrix_entry,secret);", "sum.clear();", 1),
            ("sum.multiply_add_assign(&matrix_entry,transformed);", "sum.clear();", 2),
            ("sum.multiply_add_assign(&left,&right);", "sum.clear();", 1),
            ("sum.inverse_into(&mutsecret);", "sum.clear();", 1),
            ("coefficient.forward_into(transformed);", "transformed.clear();", 2),
            ("product.forward_into(&mutmatrix_entry);", "matrix_entry.clear();", 1),
            ("secret.forward_into(&mutleft);", "left.clear();", 1),
            ("value.forward_into(&mutright);", "right.clear();", 1),
        ):
            self.assertEqual(flat.count(before), count, before)
            for site in range(count):
                self.assert_contract_mutation_rejected(flat, before, after, site)


if __name__ == "__main__":
    unittest.main()
