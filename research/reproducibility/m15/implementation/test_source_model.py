"""Semantic mutation and nonvacuity checks for the restricted source proof."""
import unittest
import source_model as m
import prove
import ntt_certificate as ntt


class SourceProofTests(unittest.TestCase):
    def obligation(self, program, name):
        return next((pre, goal) for key, pre, goal, _ in prove.queries(program) if key == name)

    def test_every_precondition_is_satisfiable(self):
        count = 0
        for _, pre, _, _ in prove.queries():
            solver = m.z3.Solver(); solver.add(pre)
            self.assertEqual(solver.check(), m.z3.sat)
            count += 1
        self.assertEqual(count, 31)

    def test_wrong_correction_bit_has_a_counterexample(self):
        p = m.Program()
        changed = m.Program(engine=p.engine.replace('(t >> 31)', '(t >> 30)', 1))
        pre, goal = self.obligation(changed, 'reduce-once')
        self.assertEqual(prove.solver_for(pre, goal).check(), m.z3.sat)

    def test_wrong_reciprocal_has_a_counterexample(self):
        p = m.Program()
        changed = m.Program(engine=p.engine.replace('(1_u64 << 32) / (Q as u64)', '(1_u64 << 32) / (Q as u64) + 1', 1))
        pre, goal = self.obligation(changed, 'quotient')
        self.assertEqual(prove.solver_for(pre, goal).check(), m.z3.sat)

    def test_changed_rounding_has_a_counterexample(self):
        p = m.Program()
        changed = m.Program(kem=p.kem.replace('u32::from(Q / 2)', 'u32::from(Q / 2 - 1)', 1))
        pre, goal = self.obligation(changed, 'compress-5')
        self.assertEqual(prove.solver_for(pre, goal).check(), m.z3.sat)

    def test_unsupported_control_flow_is_rejected(self):
        p = m.Program()
        changed = m.Program(engine=p.engine.replace('let t = x.wrapping_sub(u32::from(Q));',
            'if x == 0 { return 0; } let t = x.wrapping_sub(u32::from(Q));', 1))
        with self.assertRaises(ValueError):
            changed.call('reduce_once', [m.Value(m.z3.Int('x'), 32)])

    def test_return_width_change_is_rejected(self):
        p = m.Program()
        old = 't.wrapping_add((t >> 31) * u32::from(Q)) as u16'
        changed = m.Program(engine=p.engine.replace(old, old[:-3]+'u8', 1))
        with self.assertRaises(ValueError):
            changed.call('reduce_once', [m.Value(m.z3.Int('x'), 32)])

    def test_escaping_expression_syntax_is_rejected(self):
        for text in ('x[0]', 'x == 1', 'if true { x }', 'unsafe { x }', 'x; 0', 'x.rotate_left(1)'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                m.expression(text, {'x': m.Value(m.z3.Int('x'), 32)}, {}, [])

    def test_unsigned_cast_and_wrapping_are_exact(self):
        env = {'x': m.Value(m.z3.IntVal(0), 32), 'Q': m.Value(m.z3.IntVal(7681), 16)}
        out = m.expression('x.wrapping_sub(u32::from(Q))', env, {}, [])
        self.assertEqual(m.number(out.term), (1 << 32)-7681)
        out = m.expression('65537_u32 as u16', env, {}, [])
        self.assertEqual(m.number(out.term), 1)

    def test_canonical_domain_is_not_silently_extended(self):
        p = m.Program(); x = m.z3.IntVal(2*7681)
        out, _ = p.call('reduce_once', [m.Value(x, 32)])
        self.assertEqual(m.number(out.term), 7681)
        self.assertNotEqual(m.number(out.term), 0)

    def test_ntt_source_schedule_mutation_is_rejected(self):
        p = m.Program()
        changed = p.engine.replace('let length = 2 << stage;', 'let length = 4 << stage;', 1)
        with self.assertRaises(ValueError):
            ntt.source_guard(changed)

    def test_ntt_root_mutation_is_rejected(self):
        p = m.Program()
        changed = p.engine.replace('const PSI: u16 = 4055;', 'const PSI: u16 = 4054;', 1)
        with self.assertRaises(ValueError):
            ntt.build(changed)

    def test_ntt_mutation_of_table_binding_is_rejected(self):
        p = m.Program()
        changed = p.engine.replace('stage_twiddles(OMEGA_INVERSE);', 'stage_twiddles(OMEGA);', 1)
        with self.assertRaises(ValueError):
            ntt.source_guard(changed)

    def test_KEM_local_modulus_cannot_be_silently_substituted(self):
        p=m.Program()
        with self.assertRaises(ValueError):
            m.Program(kem=p.kem.replace('pub const Q: u16 = 7681;', 'pub const Q: u16 = 7680;', 1))

    def test_compression_import_binding_cannot_be_silently_substituted(self):
        p=m.Program()
        with self.assertRaises(ValueError):
            m.Program(kem=p.kem.replace('quotient, reduce_once,', 'quotient as different_quotient, reduce_once,', 1))

    def test_fake_commented_function_cannot_mask_a_bad_real_body(self):
        p=m.Program();_,_,raw=m.body(p.engine,'reduce_once')
        fake='// fn reduce_once(x: u32) -> u16 { '+m.strip_comments(raw).replace('\n',' ')+' }\n'
        bad=fake+p.engine.replace('(t >> 31)','(t >> 30)',1)
        pre,goal=self.obligation(m.Program(engine=bad),'reduce-once')
        self.assertEqual(prove.solver_for(pre,goal).check(),m.z3.sat)

    def test_fake_string_function_cannot_mask_a_bad_real_body(self):
        p=m.Program();_,_,raw=m.body(p.engine,'reduce_once')
        fake='const NOTE: &str = r#"fn reduce_once(x: u32) -> u16 { '+m.strip_comments(raw).replace('\n',' ')+' }"#;\n'
        bad=fake+p.engine.replace('(t >> 31)','(t >> 30)',1)
        pre,goal=self.obligation(m.Program(engine=bad),'reduce-once')
        self.assertEqual(prove.solver_for(pre,goal).check(),m.z3.sat)

    def test_fake_commented_constant_cannot_mask_a_different_modulus(self):
        p=m.Program()
        bad=p.engine.replace('const Q: u16 = 7681;','const Q: u16 = 7680;\n// const Q: u16 = 7681;',1)
        with self.assertRaises(ValueError):m.Program(engine=bad)

    def test_fake_commented_NTT_cannot_mask_a_bad_real_schedule(self):
        p=m.Program()
        fake='// fn transform(values: &mut [u16; N], twiddles: &[u16; N - 1]) { '+ntt.TEMPLATE.replace('\n',' ')+' }\n'
        bad=fake+p.engine.replace('let length = 2 << stage;','let length = 4 << stage;',1)
        with self.assertRaises(ValueError):ntt.source_guard(bad)

    def test_raw_literal_with_many_delimiter_hashes_is_masked(self):
        hashes='#'*32
        text='const TEXT: &str = r'+hashes+'"a quote: " fn pretend() { } // no comment"'+hashes+'; fn actual() {}'
        code=m.code_only(text)
        self.assertNotIn('pretend',code)
        self.assertIn('fn actual()',code)
        self.assertEqual(len(code),len(text))

    def test_table_binding_in_a_string_cannot_mask_a_changed_real_binding(self):
        p=m.Program()
        statement='const INVERSE_TWIDDLES: [u16; N - 1] = stage_twiddles(OMEGA_INVERSE);'
        bad=p.engine.replace(statement,statement.replace('OMEGA_INVERSE','OMEGA'),1)
        bad+='\nconst NOTE: &str = "'+statement+'";\n'
        with self.assertRaises(ValueError):ntt.source_guard(bad)

    def test_SMT_cosmetic_names_pass_but_changed_assertions_fail(self):
        x=m.z3.Int('x');solver=m.z3.Solver();solver.add(x>=0)
        cosmetic='(declare-fun x () Int) (assert (let ((local_alias x)) (>= local_alias 0)))'
        prove.captured_assertions_match(cosmetic,solver.assertions())
        changed='(declare-fun x () Int) (assert (> x 0))'
        with self.assertRaises(ValueError):prove.captured_assertions_match(changed,solver.assertions())


if __name__ == '__main__':
    unittest.main()
