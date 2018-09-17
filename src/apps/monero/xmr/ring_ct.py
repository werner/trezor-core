# Author: https://github.com/monero-project/mininero
# Author: Dusan Klinec, ph4r05, 2018

import gc

from apps.monero.xmr import crypto


def bp_size(outputs):
    M, logM = 1, 0
    while M <= 16 and M < outputs:
        logM += 1
        M = 1 << logM

    return 32 * (21 + outputs + 2 * logM)


def prove_range_bp(amount, last_mask=None):
    mask = last_mask if last_mask is not None else crypto.random_scalar()
    bp_proof = prove_range_bp_batch([amount], [mask])

    C = crypto.decodepoint(bp_proof.V[0])
    C = crypto.point_mul8(C)

    gc.collect()

    # Return as struct as the hash(BP_struct) != hash(BP_serialized)
    # as the original hashing does not take vector lengths into account which are dynamic
    # in the serialization scheme (and thus extraneous)
    return C, mask, bp_proof


def prove_range_bp_batch(amounts, masks):
    from apps.monero.xmr import bulletproof as bp

    bpi = bp.BulletProofBuilder()
    bp_proof = bpi.prove_batch([crypto.sc_init(a) for a in amounts], masks)
    del (bpi, bp)
    gc.collect()

    return bp_proof


def verify_bp(bp_proof, amounts=None, masks=None):
    from apps.monero.xmr import bulletproof as bp

    if amounts:
        bp_proof.V = []
        for i in range(len(amounts)):
            C = crypto.gen_c(masks[i], amounts[i])
            crypto.scalarmult_into(C, C, crypto.sc_inv_eight())
            bp_proof.V.append(crypto.encodepoint(C))

    bpi = bp.BulletProofBuilder()
    res = bpi.verify(bp_proof)
    gc.collect()

    # Return as struct as the hash(BP_struct) != hash(BP_serialized)
    # as the original hashing does not take vector lengths into account which are dynamic
    # in the serialization scheme (and thus extraneous)
    return res


def prove_range(
    amount, last_mask=None, decode=False, backend_impl=True, byte_enc=True, rsig=None
):
    """
    Range proof generator.
    In order to minimize the memory consumption and CPU usage during transaction generation the returned values
    are returned encoded.
    """
    if not backend_impl or not byte_enc or decode:
        raise ValueError("Unsupported params")

    C, a, R = None, None, None
    try:
        if rsig is None:
            rsig = bytearray(32 * (64 + 64 + 64 + 1))

        buf_ai = bytearray(4 * 9 * 64)
        buf_alpha = bytearray(4 * 9 * 64)
        C, a, R = crypto.prove_range(
            rsig, amount, last_mask, buf_ai, buf_alpha
        )  # backend returns encoded

    finally:
        import gc

        buf_ai = None
        buf_alpha = None
        gc.collect()

    return C, a, R


# Ring-ct MG sigs
# Prove:
#   c.f. http:#eprint.iacr.org/2015/1098 section 4. definition 10.
#   This does the MG sig on the "dest" part of the given key matrix, and
#   the last row is the sum of input commitments from that column - sum output commitments
#   this shows that sum inputs = sum outputs
# Ver:
#   verifies the above sig is created corretly


def ecdh_encode_into(dst, unmasked, derivation=None):
    """
    Elliptic Curve Diffie-Helman: encodes and decodes the amount b and mask a
    where C= aG + bH
    """
    sec1 = crypto.hash_to_scalar(derivation)
    sec2 = crypto.hash_to_scalar(crypto.encodeint(sec1))

    dst.mask = crypto.sc_add(unmasked.mask, sec1)
    dst.amount = crypto.sc_add(unmasked.amount, sec2)
    return dst


#
# Key image import / export
#


def generate_ring_signature(prefix_hash, image, pubs, sec, sec_idx, test=False):
    """
    Generates ring signature with key image.
    void crypto_ops::generate_ring_signature()
    """
    from trezor.utils import memcpy

    if test:
        from apps.monero.xmr import monero

        t = crypto.scalarmult_base(sec)
        if not crypto.point_eq(t, pubs[sec_idx]):
            raise ValueError("Invalid sec key")

        k_i = monero.generate_key_image(crypto.encodepoint(pubs[sec_idx]), sec)
        if not crypto.point_eq(k_i, image):
            raise ValueError("Key image invalid")
        for k in pubs:
            crypto.ge_frombytes_vartime_check(k)

    image_unp = crypto.ge_frombytes_vartime(image)
    image_pre = crypto.ge_dsm_precomp(image_unp)

    buff_off = len(prefix_hash)
    buff = bytearray(buff_off + 2 * 32 * len(pubs))
    memcpy(buff, 0, prefix_hash, 0, buff_off)
    mvbuff = memoryview(buff)

    sum = crypto.sc_0()
    k = crypto.sc_0()
    sig = []
    for i in range(len(pubs)):
        sig.append([crypto.sc_0(), crypto.sc_0()])  # c, r

    for i in range(len(pubs)):
        if i == sec_idx:
            k = crypto.random_scalar()
            tmp3 = crypto.scalarmult_base(k)
            crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp3)
            buff_off += 32

            tmp3 = crypto.hash_to_ec(crypto.encodepoint(pubs[i]))
            tmp2 = crypto.scalarmult(tmp3, k)
            crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
            buff_off += 32

        else:
            sig[i] = [crypto.random_scalar(), crypto.random_scalar()]
            tmp3 = crypto.ge_frombytes_vartime(pubs[i])
            tmp2 = crypto.ge_double_scalarmult_base_vartime(sig[i][0], tmp3, sig[i][1])
            crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
            buff_off += 32

            tmp3 = crypto.hash_to_ec(crypto.encodepoint(tmp3))
            tmp2 = crypto.ge_double_scalarmult_precomp_vartime(
                sig[i][1], tmp3, sig[i][0], image_pre
            )
            crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
            buff_off += 32

            sum = crypto.sc_add(sum, sig[i][0])

    h = crypto.hash_to_scalar(buff)
    sig[sec_idx][0] = crypto.sc_sub(h, sum)
    sig[sec_idx][1] = crypto.sc_mulsub(sig[sec_idx][0], sec, k)
    return sig


def check_ring_singature(prefix_hash, image, pubs, sig):
    from trezor.utils import memcpy

    image_unp = crypto.ge_frombytes_vartime(image)
    image_pre = crypto.ge_dsm_precomp(image_unp)

    buff_off = len(prefix_hash)
    buff = bytearray(buff_off + 2 * 32 * len(pubs))
    memcpy(buff, 0, prefix_hash, 0, buff_off)
    mvbuff = memoryview(buff)

    sum = crypto.sc_0()
    for i in range(len(pubs)):
        if crypto.sc_check(sig[i][0]) != 0 or crypto.sc_check(sig[i][1]) != 0:
            return False

        tmp3 = crypto.ge_frombytes_vartime(pubs[i])
        tmp2 = crypto.ge_double_scalarmult_base_vartime(sig[i][0], tmp3, sig[i][1])
        crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
        buff_off += 32

        tmp3 = crypto.hash_to_ec(crypto.encodepoint(pubs[i]))
        tmp2 = crypto.ge_double_scalarmult_precomp_vartime(
            sig[i][1], tmp3, sig[i][0], image_pre
        )
        crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
        buff_off += 32

        sum = crypto.sc_add(sum, sig[i][0])

    h = crypto.hash_to_scalar(buff)
    h = crypto.sc_sub(h, sum)
    return crypto.sc_isnonzero(h) == 0


def export_key_image(
    creds,
    subaddresses,
    pkey,
    tx_pub_key,
    additional_tx_pub_keys,
    out_idx,
    test=True,
    verify=True,
):
    """
    Generates key image for the TXO + signature for the key image
    """
    from apps.monero.xmr import monero

    r = monero.generate_tx_spend_and_key_image_and_derivation(
        creds, subaddresses, pkey, tx_pub_key, additional_tx_pub_keys, out_idx
    )
    xi, ki, recv_derivation = r[:3]

    phash = crypto.encodepoint(ki)
    sig = generate_ring_signature(phash, ki, [pkey], xi, 0, test)

    if verify:
        if check_ring_singature(phash, ki, [pkey], sig) != 1:
            raise ValueError("Signature error")

    return ki, sig
