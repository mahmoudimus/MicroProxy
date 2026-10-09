# A test module that never finishes loading (StdlibLoaderTest).
def _spin():
    x = 0
    for i in range(1 << 30):
        x += i
    return x

x = _spin()
