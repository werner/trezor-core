# Author: Dusan Klinec, ph4r05, 2018
#
# Resources:
# https://cr.yp.to
# https://github.com/monero-project/mininero
# https://godoc.org/github.com/agl/ed25519/edwards25519
# https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-00#section-4
# https://github.com/monero-project/research-lab

import ubinascii as binascii

from trezor.crypto import hmac, monero as tcry, pbkdf2 as tpbkdf2, random
from trezor.crypto.hashlib import sha3_256

NULL_KEY_ENC = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def random_bytes(by):
    """
    Generates X random bytes, returns byte-string
    """
    return random.bytes(by)


def keccak_factory(data=None):
    return sha3_256(data=data, keccak=True)


def get_keccak():
    return keccak_factory()


def keccak_hash(inp):
    return tcry.xmr_fast_hash(inp)


def keccak_hash_into(r, inp):
    return tcry.xmr_fast_hash(r, inp)


def keccak_2hash(inp):
    return keccak_hash(keccak_hash(inp))


def get_hmac(key, msg=None):
    return hmac.new(key, msg=msg, digestmod=keccak_factory)


def compute_hmac(key, msg=None):
    h = hmac.new(key, msg=msg, digestmod=keccak_factory)
    return h.digest()


def pbkdf2(inp, salt, length=32, count=1000, prf=None):
    """
    PBKDF2 with default PRF as HMAC-KECCAK-256
    """
    pb = tpbkdf2("hmac-sha256", inp, salt)
    pb.update(count)
    return pb.key()


#
# EC
#


def new_point():
    return tcry.ge25519_set_neutral()


def new_scalar():
    return tcry.init256_modm(0)


def decodepoint(x):
    return tcry.ge25519_unpack_vartime(x)


def decodepoint_into(r, x, offset=0):
    return tcry.ge25519_unpack_vartime(r, x, offset)


def encodepoint(pt):
    return tcry.ge25519_pack(pt)


def encodepoint_into(b, pt, offset=0):
    return tcry.ge25519_pack_into(b, pt, offset)


def decodeint(x):
    return tcry.unpack256_modm(x)


def decodeint_into_noreduce(r, x, offset=0):
    return tcry.unpack256_modm_noreduce(r, x, offset)


def decodeint_into(r, x, offset=0):
    return tcry.unpack256_modm(r, x, offset)


def encodeint(x):
    return tcry.pack256_modm(x)


def encodeint_into(b, x, offset=0):
    return tcry.pack256_modm_into(b, x, offset)


def check_ed25519point(x):
    return tcry.ge25519_check(x)


def scalarmult_base(a):
    return tcry.ge25519_scalarmult_base(a)


def scalarmult_base_into(r, a):
    return tcry.ge25519_scalarmult_base(r, a)


def scalarmult(P, e):
    return tcry.ge25519_scalarmult(P, e)


def scalarmult_into(r, P, e):
    return tcry.ge25519_scalarmult(r, P, e)


def point_add(P, Q):
    return tcry.ge25519_add(P, Q, 0)


def point_add_into(r, P, Q):
    return tcry.ge25519_add(r, P, Q, 0)


def point_sub(P, Q):
    return tcry.ge25519_add(P, Q, 1)


def point_sub_into(r, P, Q):
    return tcry.ge25519_add(r, P, Q, 1)


def point_eq(P, Q):
    return tcry.ge25519_eq(P, Q)


def point_double(P):
    return tcry.ge25519_double(P)


def point_mul8(P):
    return tcry.ge25519_mul8(P)


def point_mul8_into(r, P):
    return tcry.ge25519_mul8(r, P)


INV_EIGHT = b"\x79\x2f\xdc\xe2\x29\xe5\x06\x61\xd0\xda\x1c\x7d\xb3\x9d\xd3\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06"
INV_EIGHT_SC = decodeint(INV_EIGHT)


def sc_inv_eight():
    return INV_EIGHT_SC


#
# Zmod(order), scalar values field
#


def sc_0():
    """
    Sets 0 to the scalar value Zmod(m)
    """
    return tcry.init256_modm(0)


def sc_0_into(r):
    """
    Sets 0 to the scalar value Zmod(m)
    """
    return tcry.init256_modm(r, 0)


def sc_init(x):
    """
    Sets x to the scalar value Zmod(m)
    """
    if x >= (1 << 64):
        raise ValueError("Initialization works up to 64-bit only")
    return tcry.init256_modm(x)


def sc_init_into(r, x):
    """
    Sets x to the scalar value Zmod(m)
    """
    if x >= (1 << 64):
        raise ValueError("Initialization works up to 64-bit only")
    return tcry.init256_modm(r, x)


def sc_get64(x):
    """
    Returns 64bit value from the sc
    """
    return tcry.get256_modm(x)


def sc_check(key):
    """
    sc_check is not relevant for long-integer scalar representation.
    """
    tcry.check256_modm(key)
    return 0


def check_sc(key):
    """
    throws exception on invalid key
    """
    if sc_check(key) != 0:
        raise ValueError("Invalid scalar value")


def sc_add(aa, bb):
    """
    Scalar addition
    """
    return tcry.add256_modm(aa, bb)


def sc_add_into(r, aa, bb):
    """
    Scalar addition
    """
    return tcry.add256_modm(r, aa, bb)


def sc_sub(aa, bb):
    """
    Scalar subtraction
    """
    return tcry.sub256_modm(aa, bb)


def sc_sub_into(r, aa, bb):
    """
    Scalar subtraction
    """
    return tcry.sub256_modm(r, aa, bb)


def sc_mul(aa, bb):
    """
    Scalar multiplication
    """
    return tcry.mul256_modm(aa, bb)


def sc_mul_into(r, aa, bb):
    """
    Scalar multiplication
    """
    return tcry.mul256_modm(r, aa, bb)


def sc_isnonzero(c):
    """
    Returns true if scalar is non-zero
    """
    return not tcry.iszero256_modm(c)


def sc_eq(a, b):
    """
    Returns true if scalars are equal
    """
    return tcry.eq256_modm(a, b)


def sc_mulsub(aa, bb, cc):
    """
    (cc - aa * bb) % l
    """
    return tcry.mulsub256_modm(aa, bb, cc)


def sc_mulsub_into(r, aa, bb, cc):
    """
    (cc - aa * bb) % l
    """
    return tcry.mulsub256_modm(r, aa, bb, cc)


def sc_muladd(aa, bb, cc):
    """
    (cc + aa * bb) % l
    """
    return tcry.muladd256_modm(aa, bb, cc)


def sc_muladd_into(r, aa, bb, cc):
    """
    (cc + aa * bb) % l
    """
    return tcry.muladd256_modm(r, aa, bb, cc)


def sc_inv_into(r, x):
    """
    Modular inversion mod curve order L
    """
    return tcry.inv256_modm(r, x)


def random_scalar():
    return tcry.xmr_random_scalar()


def random_scalar_into(r):
    return tcry.xmr_random_scalar(r)


#
# GE - ed25519 group
#


def ge_double_scalarmult_base_vartime(a, A, b):
    """
    void ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2);
    r = a * A + b * B
    """
    R = tcry.ge25519_double_scalarmult_vartime(A, a, b)
    return R


def ge_double_scalarmult_precomp_vartime(a, A, b, Bi):
    """
    void ge_double_scalarmult_precomp_vartime(ge_p2 *r, const unsigned char *a, const ge_p3 *A, const unsigned char *b, const ge_dsmp Bi)
    """
    return ge_double_scalarmult_precomp_vartime2(a, A, b, Bi)


def ge_double_scalarmult_precomp_vartime2(a, Ai, b, Bi):
    """
    void ge_double_scalarmult_precomp_vartime2(ge_p2 *r, const unsigned char *a, const ge_dsmp Ai, const unsigned char *b, const ge_dsmp Bi)
    """
    return tcry.xmr_add_keys3(a, Ai, b, Bi)


def identity(byte_enc=False):
    idd = tcry.ge25519_set_neutral()
    return idd if not byte_enc else encodepoint(idd)


def identity_into(r):
    return tcry.ge25519_set_neutral(r)


def ge_frombytes_vartime_check(point):
    """
    https://www.imperialviolet.org/2013/12/25/elligator.html
    http://elligator.cr.yp.to/
    http://elligator.cr.yp.to/elligator-20130828.pdf
    """
    tcry.ge25519_check(point)
    return 0


def ge_frombytes_vartime(point):
    """
    https://www.imperialviolet.org/2013/12/25/elligator.html
    """
    ge_frombytes_vartime_check(point)
    return point


def precomp(point):
    """
    Precomputation placeholder
    """
    return point


def ge_dsm_precomp(point):
    """
    void ge_dsm_precomp(ge_dsmp r, const ge_p3 *s)
    """
    return point


#
# Monero specific
#


def cn_fast_hash(buff):
    """
    Keccak 256, original one (before changes made in SHA3 standard)
    """
    return keccak_hash(buff)


def hash_to_scalar(data, length=None):
    """
    H_s(P)
    """
    dt = data[:length] if length else data
    return tcry.xmr_hash_to_scalar(dt)


def hash_to_scalar_into(r, data, length=None):
    dt = data[:length] if length else data
    return tcry.xmr_hash_to_scalar(r, dt)


def hash_to_ec(buf):
    """
    H_p(buf)

    Code adapted from MiniNero: https://github.com/monero-project/mininero
    https://github.com/monero-project/research-lab/blob/master/whitepaper/ge_fromfe_writeup/ge_fromfe.pdf
    http://archive.is/yfINb
    """
    return tcry.xmr_hash_to_ec(buf)


def hash_to_ec_into(r, buf):
    return tcry.xmr_hash_to_ec(r, buf)


#
# XMR
#


def gen_H():
    """
    Returns point H
    8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94
    """
    return tcry.ge25519_set_h()


def scalarmult_h(i):
    return scalarmult(gen_H(), sc_init(i) if isinstance(i, int) else i)


def add_keys2(a, b, B):
    """
    aG + bB, G is basepoint
    """
    return tcry.xmr_add_keys2_vartime(a, b, B)


def add_keys2_into(r, a, b, B):
    """
    aG + bB, G is basepoint
    """
    return tcry.xmr_add_keys2_vartime(r, a, b, B)


def add_keys3(a, A, b, B):
    """
    aA + bB
    """
    return tcry.xmr_add_keys3_vartime(a, A, b, B)


def add_keys3_into(r, a, A, b, B):
    """
    aA + bB
    """
    return tcry.xmr_add_keys3_vartime(r, a, A, b, B)


def gen_c(a, amount):
    """
    Generates Pedersen commitment
    C = aG + bH
    """
    return tcry.xmr_gen_c(a, amount)


def generate_key_derivation(pub, sec):
    """
    Key derivation: 8*(key2*key1)
    """
    if sc_check(sec) != 0:
        # checks that the secret key is uniform enough...
        raise ValueError("error in sc_check in keyder")
    if ge_frombytes_vartime_check(pub) != 0:
        raise ValueError("didn't pass curve checks in keyder")

    return tcry.xmr_generate_key_derivation(pub, sec)


def derivation_to_scalar(derivation, output_index):
    """
    H_s(derivation || varint(output_index))
    """
    check_ed25519point(derivation)
    return tcry.xmr_derivation_to_scalar(derivation, output_index)


def derive_public_key(derivation, output_index, base):
    """
    H_s(derivation || varint(output_index))G + base
    """
    if ge_frombytes_vartime_check(base) != 0:  # check some conditions on the point
        raise ValueError("derive pub key bad point")
    check_ed25519point(base)

    return tcry.xmr_derive_public_key(derivation, output_index, base)


def derive_secret_key(derivation, output_index, base):
    """
    base + H_s(derivation || varint(output_index))
    """
    if sc_check(base) != 0:
        raise ValueError("cs_check in derive_secret_key")
    return tcry.xmr_derive_private_key(derivation, output_index, base)


def get_subaddress_secret_key(secret_key, major=0, minor=0):
    """
    Builds subaddress secret key from the subaddress index
    Hs(SubAddr || a || index_major || index_minor)
    """
    return tcry.xmr_get_subaddress_secret_key(major, minor, secret_key)


def prove_range(rsig, amount, last_mask=None, *args, **kwargs):
    """
    Range proof provided by the backend. Implemented in C for speed.
    """
    C, a, R = tcry.gen_range_proof(rsig, amount, last_mask, *args, **kwargs)

    # Trezor micropython extmod returns byte-serialized/flattened rsig
    return C, a, R


def b16_to_scalar(bts):
    """
    Converts hexcoded bytearray to the scalar
    """
    return decodeint(binascii.unhexlify(bts))


#
# Repr invariant
#


def hmac_point(key, point):
    """
    HMAC single point
    """
    return compute_hmac(key, encodepoint(point))


def generate_signature(data, priv):
    """
    Generate EC signature
    crypto_ops::generate_signature(const hash &prefix_hash, const public_key &pub, const secret_key &sec, signature &sig)
    """
    pub = scalarmult_base(priv)

    k = random_scalar()
    comm = scalarmult_base(k)

    buff = data + encodepoint(pub) + encodepoint(comm)
    c = hash_to_scalar(buff)
    r = sc_mulsub(priv, c, k)
    return c, r, pub


def check_signature(data, c, r, pub):
    """
    EC signature verification
    """
    check_ed25519point(pub)
    if sc_check(c) != 0 or sc_check(r) != 0:
        raise ValueError("Signature error")

    tmp2 = point_add(scalarmult(pub, c), scalarmult_base(r))
    buff = data + encodepoint(pub) + encodepoint(tmp2)
    tmp_c = hash_to_scalar(buff)
    res = sc_sub(tmp_c, c)
    return not sc_isnonzero(res)
