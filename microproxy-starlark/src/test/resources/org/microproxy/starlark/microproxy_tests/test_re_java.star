"""MicroProxy's tests of re on java.util.regex: what RE2 rejected and Java runs, and Python's
semantics the translation keeps (expected values from CPython 3)."""
load("@stdlib//re", "re")
load("@stdlib//unittest", "unittest")
load("@vendor//asserts", "asserts")


def _test_look_around_and_backreferences():
    asserts.assert_that(re.sub(r"(?<=a)b", "X", "abab cb")).is_equal_to("aXaX cb")
    asserts.assert_that(re.search(r"a(?=b)", "ab").span()).is_equal_to((0, 1))
    asserts.assert_that(re.search(r"a(?!b)", "abac").span()).is_equal_to((2, 3))
    asserts.assert_that(re.search(r"(?<!a)b", "abcb").span()).is_equal_to((3, 4))
    asserts.assert_that(re.match(r"(?P<q>[\"'])(.*?)(?P=q)", "\"hi\" there").group(2)).is_equal_to("hi")
    asserts.assert_that(re.match(r"(x)\1", "xx").group(0)).is_equal_to("xx")
    asserts.assert_that(re.split(r"(?<=,)", "a,b,c")).is_equal_to(["a,", "b,", "c"])


def _test_atomic_and_possessive():
    asserts.assert_true(re.fullmatch(r"(?>a+)b", "aab") != None)
    asserts.assert_that(re.match(r"a++a", "aaa")).is_none()


def _test_unsupported_and_errors():
    asserts.assert_fails(lambda: re.match(r"(x)(?(1)a|b)", "xa"), r"^re\.error: conditional groups are not supported")
    asserts.assert_fails(lambda: re.compile(r"(?P<a>x)(?P=b)"), r"re\.error: unknown group name 'b'")
    asserts.assert_fails(lambda: re.compile(r"(a"), r"re\.error: missing \), unterminated subpattern")
    asserts.assert_fails(lambda: re.compile(r"\p{L}"), r"re\.error: bad escape \\p")


def _test_empty_matches_as_cpython():
    asserts.assert_that(re.findall(r"a*|b", "b")).is_equal_to(["", "b", ""])
    asserts.assert_that(re.findall(r"(?m)^", "a\nb\n")).is_equal_to(["", "", ""])
    asserts.assert_that(re.sub(r"x*", "-", "abxd")).is_equal_to("-a-b--d-")


def _test_unicode_classes():
    asserts.assert_that(re.findall(r"\w+", "héllo wörld_1")).is_equal_to(["héllo", "wörld_1"])
    asserts.assert_that(re.search(r"\bwörld\b", "héllo wörld").span()).is_equal_to((6, 11))
    asserts.assert_that(re.findall(r"\d", "1١x")).is_equal_to(["1", "١"])
    asserts.assert_that(re.findall(r"(?a)\d", "1١x")).is_equal_to(["1"])
    asserts.assert_that(re.sub(r"\s+", " ", "a 　 b")).is_equal_to("a b")
    asserts.assert_true(re.match(r"(?i)é", "É") != None)


def _test_dollar_and_dot():
    asserts.assert_that(re.findall(r"x$", "x\nx\n")).is_equal_to(["x"])
    asserts.assert_that(re.findall(r"(?m)x$", "x\nx\n")).is_equal_to(["x", "x"])
    # Python's . and $ stop only at \n (Java's own would also stop at \r and U+2028)
    asserts.assert_that(re.match(r".+", "a\rb c\nd").group(0)).is_equal_to("a\rb c")
    asserts.assert_that(re.search(r"b$", "a\rb\r")).is_none()


def _test_pos_and_endpos():
    p = re.compile(r"^a")
    asserts.assert_that(p.match("ba", 1)).is_none()
    asserts.assert_that(re.compile(r"(?m)^a").match("\na", 1).span()).is_equal_to((1, 2))
    asserts.assert_that(re.compile(r"a$").search("aab", 0, 2).span()).is_equal_to((1, 2))
    asserts.assert_that(re.compile(r"\bb").search("ab", 1)).is_none()


def _suite():
    _suite = unittest.TestSuite()
    _suite.addTest(unittest.FunctionTestCase(_test_look_around_and_backreferences))
    _suite.addTest(unittest.FunctionTestCase(_test_atomic_and_possessive))
    _suite.addTest(unittest.FunctionTestCase(_test_unsupported_and_errors))
    _suite.addTest(unittest.FunctionTestCase(_test_empty_matches_as_cpython))
    _suite.addTest(unittest.FunctionTestCase(_test_unicode_classes))
    _suite.addTest(unittest.FunctionTestCase(_test_dollar_and_dot))
    _suite.addTest(unittest.FunctionTestCase(_test_pos_and_endpos))
    return _suite


_runner = unittest.TextTestRunner()
_runner.run(_suite())
