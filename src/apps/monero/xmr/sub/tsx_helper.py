from trezor.messages.MoneroAccountPublicAddress import MoneroAccountPublicAddress

from apps.monero.xmr import crypto
from apps.monero.xmr.serialize import xmrserialize
from apps.monero.xmr.serialize.readwriter import MemoryReaderWriter
from apps.monero.xmr.serialize_messages.tx_extra import (
    TxExtraAdditionalPubKeys,
    TxExtraField,
)


def absolute_output_offsets_to_relative(off):
    """
    Relative offsets, prev + cur = next.
    Helps with varint encoding size.
    """
    if len(off) == 0:
        return off
    off.sort()
    for i in range(len(off) - 1, 0, -1):
        off[i] -= off[i - 1]
    return off


def get_destination_view_key_pub(destinations, change_addr=None):
    """
    Returns destination address public view key
    """
    from apps.monero.xmr.sub.addr import addr_eq

    addr = MoneroAccountPublicAddress(
        spend_public_key=crypto.NULL_KEY_ENC, view_public_key=crypto.NULL_KEY_ENC
    )
    count = 0
    for dest in destinations:
        if dest.amount == 0:
            continue
        if change_addr and addr_eq(dest.addr, change_addr):
            continue
        if addr_eq(dest.addr, addr):
            continue
        if count > 0:
            return crypto.NULL_KEY_ENC
        addr = dest.addr
        count += 1
    return addr.view_public_key


def encrypt_payment_id(payment_id, public_key, secret_key):
    """
    Encrypts payment_id hex.
    Used in the transaction extra. Only recipient is able to decrypt.
    """
    derivation_p = crypto.generate_key_derivation(public_key, secret_key)
    derivation = bytearray(33)
    derivation = crypto.encodepoint_into(derivation, derivation_p)
    derivation[32] = 0x8b
    hash = crypto.cn_fast_hash(derivation)
    pm_copy = bytearray(payment_id)
    for i in range(8):
        pm_copy[i] ^= hash[i]
    return pm_copy


def add_tx_pub_key_to_extra(tx_extra, pub_key):
    """
    Adds public key to the extra
    """
    to_add = bytearray(33)
    to_add[0] = 1
    crypto.encodepoint_into(memoryview(to_add)[1:], pub_key)  # TX_EXTRA_TAG_PUBKEY
    return tx_extra + to_add


def add_additional_tx_pub_keys_to_extra(
    tx_extra, additional_pub_keys=None, pub_enc=None
):
    """
    Adds all pubkeys to the extra
    """
    pubs_msg = TxExtraAdditionalPubKeys(
        data=pub_enc
        if pub_enc
        else [crypto.encodepoint(x) for x in additional_pub_keys]
    )

    rw = MemoryReaderWriter()
    ar = xmrserialize.Archive(rw, True)

    # format: variant_tag (0x4) | array len varint | 32B | 32B | ...
    ar.variant(pubs_msg, TxExtraField)
    tx_extra += rw.get_buffer()
    return tx_extra
