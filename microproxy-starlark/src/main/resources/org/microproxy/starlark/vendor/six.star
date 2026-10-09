"""
This module is not really needed but it's here for posterity sake
"""
load("@stdlib//larky", larky="larky")
load("@stdlib//operator", operator="operator")
load("@stdlib//struct", struct="struct")
load("@stdlib//types", types="types")


# MicroProxy: tobytes and tostr replace starlarky's @vendor//Crypto/Util/py3compat.
def tobytes(s, encoding="latin-1"):
    if types.is_bytes(s) or types.is_bytearray(s):
        return bytes(s)
    elif types.is_string(s):
        return bytes(s, encoding=encoding)
    return bytes([s]) if types.is_int(s) else bytes(s)


def tostr(bs):
    if types.is_string(bs):
        return bs
    return bs.decode("latin-1")

def _int2byte(x):
    return struct.pack(">B", x)


def reraise(tp, value, tb=None):
    if value == None:
       value = tp()
    if tb != None and getattr(value, '__traceback__', None) == tb:
       fail(value.with_traceback(tb))
    fail(value)


six = larky.struct(
    ensure_binary=tobytes,
    ensure_str=tostr,
    int2byte=_int2byte,
    byte2int=operator.itemgetter(0),
    reraise=reraise
)