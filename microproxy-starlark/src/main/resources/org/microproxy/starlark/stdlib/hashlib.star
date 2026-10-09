"""
#.  Copyright (C) 2005-2010   Gregory P. Smith (greg@krypto.org)
#  Licensed to PSF under a Contributor Agreement.
#
hashlib module - A common interface to many hash functions.
new(name, data=b'', **kwargs) - returns a new hash object implementing the
                                given hash function; initializing the hash
                                using the given binary data.
Named constructor functions are also available, these are faster
than using new(name):
md5(), sha1(), sha224(), sha256(), sha384(), sha512(), sha512_224(), sha512_256(),
sha3_224, sha3_256, sha3_384, sha3_512. (MicroProxy: these run on the JDK's
MessageDigest; blake2b, blake2s, shake_128 and shake_256 are not available and fail
with "unsupported hash type".)
More algorithms may be available on your platform but the above are guaranteed
to exist.  See the algorithms_guaranteed and algorithms_available attributes
to find out what algorithm names can be passed to new().
NOTE: If you want the adler32 or crc32 hash functions they are available in
the zlib module.
Choose your hash function wisely.  Some have known collision weaknesses.
sha384 and sha512 will be slow on 32 bit platforms.
Hash objects have these methods:
 - update(data): Update the hash object with the bytes in data. Repeated calls
                 are equivalent to a single call with the concatenation of all
                 the arguments.
 - digest():     Return the digest of the bytes passed to the update() method
                 so far as a bytes object.
 - hexdigest():  Like digest() except the digest is returned as a string
                 of double length, containing only hexadecimal digits.
 - copy():       Return a copy (clone) of the hash object. This can be used to
                 efficiently compute the digests of datas that share a common
                 initial substring.
For example, to obtain the digest of the byte string 'Nobody inspects the
spammish repetition':
    >>> import hashlib
    >>> m = hashlib.md5()
    >>> m.update(b"Nobody inspects")
    >>> m.update(b" the spammish repetition")
    >>> m.digest()
    b'\\xbbd\\x9c\\x83\\xdd\\x1e\\xa5\\xc9\\xd9\\xde\\xc9\\xa1\\x8d\\xf0\\xff\\xe9'
More condensed:
    >>> hashlib.sha224(b"Nobody inspects the spammish repetition").hexdigest()
    'a4337bc45a8fc544c03f52dc550cd6e1e87021bc896588bd79e901e2'
"""
load("@stdlib//larky", larky="larky")
load("@stdlib//types", types="types")
load("@stdlib//jhashlib", _jhashlib="jhashlib")

# MicroProxy: the digests come from the JDK (@stdlib//jhashlib) instead of
# starlarky's @vendor//Crypto/Hash modules (BouncyCastle).


def _constructor(name):
    def new(data=b'', **kwargs):
        # kwargs: usedforsecurity (accepted and ignored, as by CPython)
        return _jhashlib.new(name, data)
    return new


def _unavailable(name):
    def new(*args, **kwargs):
        # fails with "unsupported hash type <name> (...)"
        return _jhashlib.new(name)
    return new


__hashes = dict(
    md5=_constructor("md5"),
    sha=_constructor("sha1"),
    sha1=_constructor("sha1"),
    sha224=_constructor("sha224"),
    sha256=_constructor("sha256"),
    sha384=_constructor("sha384"),
    sha512=_constructor("sha512"),
    sha512_224=_constructor("sha512_224"),
    sha512_256=_constructor("sha512_256"),
    sha3_224=_constructor("sha3_224"),
    sha3_256=_constructor("sha3_256"),
    sha3_384=_constructor("sha3_384"),
    sha3_512=_constructor("sha3_512"),
    blake2b=_unavailable("blake2b"),
    blake2s=_unavailable("blake2s"),
    shake_128=_unavailable("shake_128"),
    shake_256=_unavailable("shake_256"),
)

# Other spellings CPython's hashlib.new accepts (OpenSSL's names, matched
# case-insensitively), mapped to the constructor names above.
_OPENSSL_NAMES = {
    "md5": "md5",
    "ssl3-md5": "md5",
    "sha1": "sha1",
    "sha-1": "sha1",
    "ssl3-sha1": "sha1",
    "sha224": "sha224",
    "sha-224": "sha224",
    "sha2-224": "sha224",
    "sha256": "sha256",
    "sha-256": "sha256",
    "sha2-256": "sha256",
    "sha384": "sha384",
    "sha-384": "sha384",
    "sha2-384": "sha384",
    "sha512": "sha512",
    "sha-512": "sha512",
    "sha2-512": "sha512",
    "sha512-224": "sha512_224",
    "sha2-512/224": "sha512_224",
    "sha512-256": "sha512_256",
    "sha2-512/256": "sha512_256",
    "sha3-224": "sha3_224",
    "sha3-256": "sha3_256",
    "sha3-384": "sha3_384",
    "sha3-512": "sha3_512",
    "blake2s256": "blake2s",
    "blake2b512": "blake2b",
    "shake128": "shake_128",
    "shake256": "shake_256",
}

algorithms_guaranteed = (
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
)
algorithms_available = algorithms_guaranteed + ("sha512_224", "sha512_256")


def _new(name, data=b'', **kwargs):
    """new(name, data=b'') - Return a new hashing object using the named algorithm;
    optionally initialized with data (which must be a bytes-like object).
    """
    if not types.is_string(name):
        fail("new() argument 'name' must be str, not %s" % type(name))
    if name not in __hashes or name == "sha":
        canonical = _OPENSSL_NAMES.get(name.lower())
        if canonical == None:
            fail("unsupported hash type %s" % name)
        name = canonical
    return __hashes[name](data, **kwargs)


def _pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
    """Password based key derivation function 2 (PKCS #5 v2.0) with HMAC as
    pseudorandom function."""
    return _jhashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)


hashlib = larky.struct(
    __name__='hashlib',
    new=_new,
    pbkdf2_hmac=_pbkdf2_hmac,
    algorithms_guaranteed=algorithms_guaranteed,
    algorithms_available=algorithms_available,
    **__hashes
)
