import unittest

from DNScanner.validation import (
    InvalidDomainError,
    is_valid_domain,
    normalize_domain,
)


class TestNormalize(unittest.TestCase):
    def test_strips_scheme_path_port(self):
        self.assertEqual(
            normalize_domain("https://www.Example.com:443/path?x=1"),
            "www.example.com",
        )

    def test_strips_credentials(self):
        self.assertEqual(
            normalize_domain("http://user:pass@host.example.org/"),
            "host.example.org",
        )

    def test_trailing_dot_and_case(self):
        self.assertEqual(normalize_domain("EXAMPLE.COM."), "example.com")

    def test_plain(self):
        self.assertEqual(normalize_domain("sub.domain.co.uk"), "sub.domain.co.uk")

    def test_empty_raises(self):
        with self.assertRaises(InvalidDomainError):
            normalize_domain("   ")

    def test_none_raises(self):
        with self.assertRaises(InvalidDomainError):
            normalize_domain(None)

    def test_garbage_raises(self):
        with self.assertRaises(InvalidDomainError):
            normalize_domain("http:// /")


class TestValid(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(is_valid_domain("example.com"))
        self.assertTrue(is_valid_domain("a.b.c.example.com"))

    def test_invalid(self):
        self.assertFalse(is_valid_domain(""))
        self.assertFalse(is_valid_domain("no_underscore.com"))
        self.assertFalse(is_valid_domain("-bad.com"))
        self.assertFalse(is_valid_domain("nodot"))
        self.assertFalse(is_valid_domain("a" * 260 + ".com"))


if __name__ == "__main__":
    unittest.main()
