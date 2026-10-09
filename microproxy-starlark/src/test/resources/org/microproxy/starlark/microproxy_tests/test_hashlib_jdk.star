"""MicroProxy's tests of hashlib and hmac on the JDK (expected values from CPython 3)."""
load("@stdlib//hashlib", "hashlib")
load("@stdlib//hmac", "hmac")
load("@stdlib//unittest", "unittest")
load("@vendor//asserts", "asserts")

_FOX = b"The quick brown fox jumps over the lazy dog"


def _test_hmac():
    asserts.assert_that(hmac.new(b"key", _FOX, "sha256").hexdigest()).is_equal_to(
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
    asserts.assert_that(hmac.new(b"key", _FOX, hashlib.md5).hexdigest()).is_equal_to(
        "80070713463e7749b90c2dc24911e275")
    asserts.assert_that(hmac.new(b"", b"", "sha1").hexdigest()).is_equal_to(
        "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d")
    h = hmac.new(b"key", digestmod="sha256")
    h.update(_FOX)
    asserts.assert_that(h.digest()).is_equal_to(hmac.digest(b"key", _FOX, "sha256"))
    asserts.assert_that(h.name).is_equal_to("hmac-sha256")
    asserts.assert_that(h.digest_size).is_equal_to(32)
    asserts.assert_fails(lambda: hmac.new(b"key", _FOX), "Missing required parameter 'digestmod'")
    asserts.assert_fails(lambda: hmac.new(b"key", _FOX, "blake2b"), "unsupported hash type blake2b")


def _test_compare_digest():
    asserts.assert_true(hmac.compare_digest(b"abc", b"abc"))
    asserts.assert_false(hmac.compare_digest(b"abc", b"abd"))
    asserts.assert_true(hmac.compare_digest("abc", "abc"))
    asserts.assert_fails(lambda: hmac.compare_digest("abc", b"abc"), "unsupported operand")


def _test_sha3_and_truncated_sha512():
    asserts.assert_that(hashlib.sha3_256(b"abc").hexdigest()).is_equal_to(
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
    asserts.assert_that(hashlib.new("SHA3-256", b"abc").hexdigest()).is_equal_to(
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
    asserts.assert_that(hashlib.sha512_224(b"abc").hexdigest()).is_equal_to(
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa")


def _test_hash_object():
    h = hashlib.sha256()
    h.update(b"a")
    c = h.copy()
    c.update(b"b")
    asserts.assert_that(h.hexdigest()).is_equal_to(
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")
    asserts.assert_that(c.hexdigest()).is_equal_to(
        "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603")
    asserts.assert_that((h.name, h.digest_size, h.block_size)).is_equal_to(("sha256", 32, 64))
    asserts.assert_fails(lambda: hashlib.sha256("text"), "Strings must be encoded before hashing")
    asserts.assert_fails(lambda: hashlib.blake2b(b"x"), "unsupported hash type blake2b")


def _test_pbkdf2_hmac():
    asserts.assert_that(hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 2, 20).hex()).is_equal_to(
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8e")
    asserts.assert_that(hashlib.pbkdf2_hmac("sha1", b"password", b"salt", 4096).hex()).is_equal_to(
        "4b007901b765489abead49d926f721d065a429c1")


def _suite():
    _suite = unittest.TestSuite()
    _suite.addTest(unittest.FunctionTestCase(_test_hmac))
    _suite.addTest(unittest.FunctionTestCase(_test_compare_digest))
    _suite.addTest(unittest.FunctionTestCase(_test_sha3_and_truncated_sha512))
    _suite.addTest(unittest.FunctionTestCase(_test_hash_object))
    _suite.addTest(unittest.FunctionTestCase(_test_pbkdf2_hmac))
    return _suite


_runner = unittest.TextTestRunner()
_runner.run(_suite())
