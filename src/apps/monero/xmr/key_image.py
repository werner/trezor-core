#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


from apps.monero.xmr.serialize import xmrtypes, xmrserialize
from apps.monero.xmr import ring_ct, crypto, common, monero


class SubAddrIndicesList(xmrserialize.MessageType):
    __slots__ = ['account', 'minor_indices']
    MFIELDS = [
        ('account', xmrserialize.UVarintType),
        ('minor_indices', xmrserialize.ContainerType, xmrserialize.UVarintType),
    ]


class KeyImageExportInit(xmrserialize.MessageType):
    """
    Initializes key image sync. Commitment
    """
    __slots__ = ['num', 'hash', 'subs']
    MFIELDS = [
        ('num', xmrserialize.UVarintType),  # number of outputs to gen
        ('hash', xmrtypes.Hash),  # aggregate hash commitment
        ('subs', xmrserialize.ContainerType, SubAddrIndicesList),  # aggregated sub addresses indices
    ]


class TransferDetails(xmrserialize.MessageType):
    """
    Transfer details for key image sync needs
    """
    __slots__ = ['out_key', 'tx_pub_key', 'additional_tx_pub_keys', 'm_internal_output_index']
    MFIELDS = [
        ('out_key', xmrtypes.ECPublicKey),
        ('tx_pub_key', xmrtypes.ECPublicKey),
        ('additional_tx_pub_keys', xmrserialize.ContainerType, xmrtypes.ECPublicKey),
        ('m_internal_output_index', xmrserialize.UVarintType),
    ]


class ExportedKeyImage(xmrserialize.MessageType):
    """
    Exported key image
    """
    __slots__ = ['iv', 'tag', 'blob']
    MFIELDS = [
        ('iv', xmrserialize.BlobType),   # enc IV
        ('tag', xmrserialize.BlobType),  # enc tag
        ('blob', xmrserialize.BlobType),  # encrypted ki || sig
    ]


def compute_hash(rr):
    """
    Hash over output to ki-sync
    :param rr:
    :type rr: TransferDetails
    :return:
    """
    buff = b''
    buff += rr.out_key
    buff += rr.tx_pub_key
    if rr.additional_tx_pub_keys:
        buff += b''.join(rr.additional_tx_pub_keys)
    buff += xmrserialize.dump_uvarint_b(rr.m_internal_output_index)

    return crypto.cn_fast_hash(buff)


async def export_key_image(creds, subaddresses, td):
    """
    Key image export
    :param creds:
    :param subaddresses:
    :param td:
    :return:
    """
    out_key = crypto.decodepoint(td.out_key)
    tx_pub_key = crypto.decodepoint(td.tx_pub_key)
    additional_tx_pub_keys = []
    if not common.is_empty(td.additional_tx_pub_keys):
        additional_tx_pub_keys = [crypto.decodepoint(x) for x in td.additional_tx_pub_keys]

    ki, sig = ring_ct.export_key_image(creds, subaddresses, out_key, tx_pub_key,
                                       additional_tx_pub_keys, td.m_internal_output_index)

    return ki, sig





