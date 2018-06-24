#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from apps.common import seed
from apps.monero.xmr import crypto
from apps.monero.xmr import monero
from apps.monero.trezor import trezor_iface

MONERO_CURVE = 'ed25519-keccak'


async def monero_get_creds(ctx, address_n=None, network_type=None):
    address_n = address_n or ()
    node = await seed.derive_node(ctx, address_n, MONERO_CURVE)
    to_hash = node.chain_code() + node.private_key()
    hashed = crypto.cn_fast_hash(to_hash)
    keys = monero.generate_monero_keys(hashed)  # spend_sec, spend_pub, view_sec, view_pub
    creds = monero.AccountCreds.new_wallet(keys[2], keys[0], network_type)
    return creds


def get_interface(ctx):
    return trezor_iface.get_iface(ctx)


def exc2str(e):
    return str(e)

