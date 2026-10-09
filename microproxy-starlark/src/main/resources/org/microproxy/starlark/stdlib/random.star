"""Random variable generators.
    bytes
    -----
           uniform bytes (values between 0 and 255)
    integers
    --------
           uniform within range
    sequences
    ---------
           pick random element
           pick random sample
           pick weighted random sample
           generate random permutation
    distributions on the real line:
    ------------------------------
           uniform
           triangular
           normal (Gaussian)
           lognormal
           negative exponential
           gamma
           beta
           pareto
           Weibull
    distributions on the circle (angles 0 to 2pi)
    ---------------------------------------------
           circular uniform
           von Mises
General notes on the underlying Mersenne Twister core generator:
* The period is 2**19937-1.
* It is one of the most extensively tested generators in existence.
* The random() method is implemented in C, executes in a single Python step,
  and is, therefore, threadsafe.
"""

load("@stdlib//larky", larky="larky")
load("@stdlib//jrandom", _jrandom="jrandom")

# MicroProxy: the generator is the JDK's SecureRandom (@stdlib//jrandom), not
# a seedable Mersenne Twister; starlarky's came from @stdlib//jcrypto.

random = larky.struct(
    getrandbits=_jrandom.getrandbits,
    randbytes=_jrandom.randbytes,
    randrange=_jrandom.randrange,
    randint=_jrandom.randint,
    random=_jrandom.random,
    uniform=_jrandom.uniform,
    choice=_jrandom.choice,
    shuffle=_jrandom.shuffle,
    sample=_jrandom.sample,
    urandom=_jrandom.urandom
)


getrandbits = random.getrandbits
randrange = random.randrange
randint = random.randint
choice = random.choice
shuffle = random.shuffle
sample = random.sample
urandom = random.urandom
randbytes = random.randbytes
uniform = random.uniform
