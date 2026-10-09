"""HMAC (Keyed-Hashing for Message Authentication) module.

Implements the HMAC algorithm as described by RFC 2104, with Python's hmac API:

    >>> load("@stdlib//hmac", "hmac")
    >>> hmac.new(b"key", b"message", "sha256").hexdigest()
    >>> hmac.digest(b"key", b"message", "sha256")
    >>> hmac.compare_digest(a, b)

digestmod is a hashlib name ("sha256") or a hashlib constructor (hashlib.sha256).
(MicroProxy: written for MicroProxy on the JDK's Mac, through @stdlib//jhashlib.)
"""
load("@stdlib//larky", larky="larky")
load("@stdlib//types", types="types")
load("@stdlib//jhashlib", _jhashlib="jhashlib")


def _digest_name(digestmod):
    if types.is_string(digestmod):
        if digestmod == "":
            fail("TypeError: Missing required parameter 'digestmod'.")
        return digestmod.lower().replace("-", "")
    if types.is_callable(digestmod):
        # a hashlib constructor: its hash object knows its name
        return digestmod().name
    if hasattr(digestmod, "name"):
        return digestmod.name
    fail("TypeError: digestmod must be a hash name or a hashlib constructor, not %s" % type(digestmod))


def new(key, msg=None, digestmod=""):
    """Create a new hashing object and return it.

    key: bytes or buffer, The starting key for the hash.
    msg: bytes or buffer, Initial input for the hash, or None.
    digestmod: A hash name suitable for hashlib.new() (*required*), or a
               hashlib constructor.
    """
    return _jhashlib.hmac(key, msg, _digest_name(digestmod))


def digest(key, msg, digest):
    """Fast inline implementation of HMAC: the MAC of msg with key, as bytes."""
    return _jhashlib.hmac(key, msg, _digest_name(digest)).digest()


hmac = larky.struct(
    __name__="hmac",
    new=new,
    HMAC=new,
    digest=digest,
    compare_digest=_jhashlib.compare_digest,
)
compare_digest = _jhashlib.compare_digest
