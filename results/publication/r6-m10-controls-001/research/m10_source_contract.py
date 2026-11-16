"""Reviewed M10-to-M09 ownership correspondence, not a Rust semantics proof.

The new fragments fix primitive framing, output destinations and selection
direction. Only those exact fragments are mapped to the already reviewed M09
call sites before the historical contracts run. Historical parsers and frozen
sources stay unchanged. This source check cannot establish compiled erasure.
"""
import re


def flat(text):
    return re.sub(r"\s+", "", text)


def correspondence(source):
    text = flat(source)
    reset_anchors = 0
    output_anchors = 0
    copied_output = """// Copy the API output explicitly so the local selection owner keeps its
        // Drop. Moving `key` left its address-taken stack source unwiped in the
        // first two M10 PC images; the final emitted output path is reviewed.
        SharedSecret(Zeroizing::new(*key))"""
    if flat(copied_output) in text:
        if text.count(flat(copied_output)) != 1:
            raise ValueError("reviewed R1 source contract changed; M10 copied output ambiguous")
        text = text.replace(flat(copied_output), "SharedSecret(key)", 1)
        output_anchors = 1
    # Variant 1 remains replayable on its frozen source. Variant 2 keeps the
    # absorber borrowed through finalization, so its Drop covers its storage.
    reset_import = "use shake::digest::ExtendableOutputReset;"
    if flat(reset_import) in text or "finalize_xof_reset" in text:
        if text.count(flat(reset_import)) != 1:
            raise ValueError("reviewed R1 source contract changed; M10 reset trait absent/ambiguous")
        before = "h.finalize_xof_reset().read(&mut out[..]);"
        if text.count(flat(before)) != 1:
            raise ValueError("reviewed R1 source contract changed; M10 borrowed reset missing/ambiguous")
        text = text.replace(flat(before), flat("h.finalize_xof().read(&mut out[..]);"), 1)
        reset_anchors = 2
    if output_anchors and not reset_anchors:
        raise ValueError("reviewed R1 source contract changed; M10 copied-output variant requires borrowed XOF")
    anchors = [
        "use ctutils::{Choice, CtAssign, CtEq};",
        r'''fn hash_public(ek: &[u8]) -> [u8; 32] {
            let mut h = Sha3_256::new();
            Digest::update(&mut h, TAG);
            Digest::update(&mut h, b"H\0");
            Digest::update(&mut h, ek);
            h.finalize().into()
        }''',
        '''fn derive_into(label: &[u8], parts: &[&[u8]], out: &mut [u8; 64]) {
            let mut h = Sha3_512::new();
            Digest::update(&mut h, TAG);
            Digest::update(&mut h, label);
            for p in parts { Digest::update(&mut h, p); }
            // Borrow both state and destination: no filled digest/owner is returned
            // through this internal boundary. The dependency's zeroize feature also
            // wipes its state on drop; register/ABI copies need separate image review.
            Digest::finalize_into_reset(&mut h, out.into());
        }''',
        '''#[cfg(any(test, feature = "research-vectors"))]
            fn derive(label: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
                let mut out = Zeroizing::new([0; 64]);
                derive_into(label, parts, &mut out); out
            }''',
        '''fn xof_into<const L: usize>(label: &[u8], parts: &[&[u8]], out: &mut [u8; L]) {
            let mut h = Shake256::default();
            h.update(TAG); h.update(label);
            for p in parts { h.update(p); }
            h.finalize_xof().read(&mut out[..]);
        }''',
        '''#[cfg(any(test, feature = "research-vectors"))]
            fn xof<const L: usize>(label: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; L]> {
                let mut out = Zeroizing::new([0; L]);
                xof_into(label, parts, &mut out); out
            }''',
        '''#[inline(never)]
            fn assign_shared_secret_into(out: &mut [u8; 32], good: &[u8; 32], valid: Choice) {
                out.ct_assign(good, valid);
            }''',
        r'''let mut expected = Zeroizing::new([0; 32]);
            xof_into(b"J\0", &[&dk.0[PRIVATE_KEY_BYTES - 32..], altered.as_bytes()],
                &mut expected,);''',
    ]
    for fragment in anchors:
        anchor = flat(fragment)
        if text.count(anchor) != 1:
            raise ValueError("reviewed R1 source contract changed; M10 fragment missing/ambiguous: " + anchor)

    substitutions = (
        (r'''let mut bytes = Zeroizing::new([0; 192]);
             xof_into(b"N\0", &[seed, &[nonce]], &mut bytes);''',
         r'''let bytes = xof::<192>(b"N\0", &[seed, &[nonce]]);'''),
        (r'''let mut expanded = Zeroizing::new([0; 64]);
             derive_into(b"KG\0", &[d, &[6]], &mut expanded);''',
         r'''let expanded = derive(b"KG\0", &[d, &[6]]);'''),
        (r'''let mut material = Zeroizing::new([0; 64]);
             derive_into(b"G\0", &[m, &hash_public(ek.as_bytes())], &mut material);''',
         r'''let material = derive(b"G\0", &[m, &hash_public(ek.as_bytes())]);'''),
        (r'''let mut material = Zeroizing::new([0; 64]);
             derive_into(b"G\0", &[&m[..], &dk.0[offset..offset + 32]], &mut material);''',
         r'''let material = derive(b"G\0", &[&m[..], &dk.0[offset..offset + 32]]);'''),
        (r'''let mut key = Zeroizing::new([0; 32]);
             xof_into(b"J\0", &[&dk.0[offset + 32..], c.as_bytes()], &mut key);
             assign_shared_secret_into(&mut key,
                 material[..32].try_into().expect("fixed favourable key view"),
                 c.as_bytes().ct_eq(&cp[..]),);
             SharedSecret(key)''',
         r'''let fallback = xof::<32>(b"J\0", &[&dk.0[offset + 32..], c.as_bytes()]);
             let mut good = Zeroizing::new([0; 32]);
             good.copy_from_slice(&material[..32]);
             SharedSecret(Zeroizing::new(
                 (*fallback).ct_select(&*good, c.as_bytes().ct_eq(&cp[..])),))'''),
    )
    for before, after in substitutions:
        before, after = flat(before), flat(after)
        if text.count(before) != 1:
            raise ValueError("reviewed R1 source contract changed; M10 correspondence missing/ambiguous: " + before)
        text = text.replace(before, after, 1)
    return text, len(anchors) + len(substitutions) + reset_anchors + output_anchors
