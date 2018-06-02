#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii

from apps.common import seed
from apps.monero.xmr import crypto
from apps.monero.xmr import monero
from apps.wallet.get_address import _show_address, _show_qr

from trezor.crypto.hashlib import sha256
from trezor.messages.MoneroAddress import MoneroAddress

MONERO_CURVE = 'ed25519-keccak'


async def monero_get_creds(ctx, address_n=None, network_type=None):
    address_n = address_n or ()
    node = await seed.derive_node(ctx, address_n, MONERO_CURVE)
    to_hash = node.chain_code() + binascii.unhexlify(node.private_key())
    hashed = crypto.cn_fast_hash(to_hash)
    keys = monero.generate_monero_keys(hashed)  # spend_sec, spend_pub, view_sec, view_pub
    creds = monero.AccountCreds.new_wallet(keys[2], keys[1], network_type)
    return creds

