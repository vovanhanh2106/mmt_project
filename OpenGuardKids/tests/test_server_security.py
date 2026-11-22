import _path  # noqa
import os, unittest, base64
from ogk_server import security as S


class TestSecurity(unittest.TestCase):
    def test_password_hash_and_policy(self):
        h = S.hash_password("MatKhau12345"); self.assertTrue(h.startswith("scrypt$"))
        self.assertTrue(S.verify_password("MatKhau12345", h)); self.assertFalse(S.verify_password("matkhau12345", h))
        self.assertTrue(S.password_problems("ngan")); self.assertEqual(S.password_problems("MatKhau12345"), [])
    def test_same_password_different_hash(self):
        self.assertNotEqual(S.hash_password("MatKhau12345"), S.hash_password("MatKhau12345"))
    def test_token_expiry_and_forgery(self):
        k = b"k" * 32
        self.assertEqual(S.verify_token(k, S.make_token(k, {"d": 3}, 60))["d"], 3)
        self.assertIsNone(S.verify_token(k, S.make_token(k, {"d": 3}, -1)))
        t = S.make_token(k, {"d": 3}, 60); body, sig = t.split(".")
        forged = S.b64(b'{"d":99,"exp":9999999999}') + "." + sig
        self.assertIsNone(S.verify_token(k, forged))
    def test_aes_gcm_roundtrip_and_tamper(self):
        c = S.FieldCipher(os.urandom(32)); t = c.encrypt("Bé An"); self.assertEqual(c.decrypt_str(t), "Bé An")
        raw = bytearray(S.unb64(t)); raw[-1] ^= 1
        with self.assertRaises(Exception): c.decrypt(S.b64(bytes(raw)))
    def test_totp_rfc6238_vector(self):
        self.assertEqual(S.totp_code(base64.b32encode(b"12345678901234567890").decode(), 59, 30, 8), "94287082")
    def test_rate_limiter(self):
        r = S.RateLimiter(); self.assertEqual([r.allow("a", 2, 60) for _ in range(3)], [True, True, False]); self.assertTrue(r.allow("b", 2, 60))
    def test_pairing_code_shape(self):
        c = S.pairing_code(); self.assertEqual(len(c), 8); self.assertTrue(set(c) <= set(S.PAIR_ALPHABET))


class TestNetEnforce(unittest.TestCase):
    def test_firewall_complement_keeps_upstream_only(self):
        import ipaddress
        from ogk_agent.netenforce import complement_ranges
        nets = [ipaddress.ip_network(x) for x in complement_ranges(["1.1.1.1"])]
        inside = lambda ip: any(ipaddress.ip_address(ip) in n for n in nets)
        self.assertFalse(inside("1.1.1.1")); self.assertFalse(inside("127.0.0.1")); self.assertTrue(inside("8.8.8.8"))


class TestPinning(unittest.TestCase):
    def test_pin_compare(self):
        import hashlib
        from ogk_agent.sync import verify_pin
        der = b"cert-bytes"; pin = hashlib.sha256(der).hexdigest()
        self.assertTrue(verify_pin(der, pin)); self.assertTrue(verify_pin(der, pin.upper())); self.assertFalse(verify_pin(b"other", pin))


if __name__ == "__main__":
    unittest.main()
