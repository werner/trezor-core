#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from apps.monero.xmr.serialize.int_serialize import dump_uvarint_b
from apps.monero.xmr.serialize.base_types import UVarintType
from apps.monero.xmr.serialize.message_types import MessageType, ContainerType, BlobType
from apps.monero.xmr.serialize.messages.base import ECPublicKey, Hash

from apps.monero.xmr import ring_ct, crypto, common


class SubAddrIndicesList(MessageType):
    __slots__ = ['account', 'minor_indices']
    MFIELDS = [
        ('account', UVarintType),
        ('minor_indices', ContainerType, UVarintType),
    ]


class KeyImageExportInit(MessageType):
    """
    Initializes key image sync. Commitment
    """
    __slots__ = ['num', 'hash', 'subs']
    MFIELDS = [
        ('num', UVarintType),  # number of outputs to gen
        ('hash', Hash),  # aggregate hash commitment
        ('subs', ContainerType, SubAddrIndicesList),  # aggregated sub addresses indices
    ]


class TransferDetails(MessageType):
    """
    Transfer details for key image sync needs
    """
    __slots__ = ['out_key', 'tx_pub_key', 'additional_tx_pub_keys', 'm_internal_output_index']
    MFIELDS = [
        ('out_key', ECPublicKey),
        ('tx_pub_key', ECPublicKey),
        ('additional_tx_pub_keys', ContainerType,
         ECPublicKey),
        ('m_internal_output_index', UVarintType),
    ]


class ExportedKeyImage(MessageType):
    """
    Exported key image
    """
    __slots__ = ['iv', 'tag', 'blob']
    MFIELDS = [
        ('iv', BlobType),   # enc IV
        ('tag', BlobType),  # enc tag
        ('blob', BlobType),  # encrypted ki || sig
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
    buff += dump_uvarint_b(rr.m_internal_output_index)

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
