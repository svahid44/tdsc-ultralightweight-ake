"""Regression tests for offline attacker calculations (synthetic data only)."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'src' / 'attacker_node.py'
spec = importlib.util.spec_from_file_location('attacker_node', PATH)
attack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(attack)


class KeyRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.sk = 123456789
        self.a = 987654321
        self.pk = attack.public_of_scalar(self.sk)
        self.ap = attack.public_of_scalar(self.a)
        self.observation = lambda phase: attack.demo_observation(phase, self.sk, self.a, "TEST-ONLY", self.pk, self.ap)

    def test_attack_1(self):
        result, key = attack.recover(self.observation("phase2"), self.observation("phase3"), "1")
        self.assertEqual(result['result'], 'PASS')
        self.assertEqual(int(key['sk_smd_hex'], 16), self.sk)

    def test_attack_2(self):
        result, key = attack.recover(self.observation("phase2"), self.observation("phase2"), "2")
        self.assertEqual(result['result'], 'PASS')
        self.assertEqual(int(key['sk_smd_hex'], 16), self.sk)

    def test_attack_3(self):
        result, key = attack.recover(self.observation("phase3"), self.observation("phase3"), "3")
        self.assertEqual(result['result'], 'PASS')
        self.assertEqual(int(key['sk_smd_hex'], 16), self.sk)

    def test_public_key_mismatch(self):
        first, second = self.observation('phase3'), self.observation('phase3')
        second['pk_smd_sec1'] = attack.b64enc(attack.public_of_scalar(444))
        with self.assertRaises(attack.ObservationError):
            attack.recover(first, second, '3')

    def test_token_tamper(self):
        first, second = self.observation('phase3'), self.observation('phase3')
        scalar = (int.from_bytes(attack.b64dec(second['v1_smd'], 'v1_smd'), 'big') + 1) % attack.N
        second['v1_smd'] = attack.b64enc(scalar.to_bytes(32, 'big'))
        report, _ = attack.recover(first, second, '3')
        self.assertEqual(report['result'], 'FAIL')

    def test_no_unsafe_pem_import(self):
        self.assertNotIn('sk_smd.pem', PATH.read_text())

if __name__ == '__main__':
    unittest.main()
