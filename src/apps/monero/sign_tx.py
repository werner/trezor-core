#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


from apps.monero import trezor_iface, trezor_misc
from apps.monero.xmr.serialize import xmrtypes, xmrserialize
from apps.monero.xmr.monero import TsxData, classify_subaddresses
from apps.monero.xmr import monero, mlsag2, ring_ct, crypto, common, key_image, trezor
from apps.monero.xmr.enc import chacha_poly
from apps.monero.trezor_lite import TrezorLite

from apps.monero import layout
from trezor.messages.MoneroRespError import MoneroRespError
from trezor.messages.MoneroTsxSign import MoneroTsxSign


TX_STATE = None


async def layout_sign_tx(ctx, msg: MoneroTsxSign):
    global TX_STATE
    if TX_STATE is None or msg.init:
        TX_STATE = TrezorLite()

    try:
        res = await TX_STATE.sign(ctx, msg)
        if await TX_STATE.should_purge():
            TX_STATE = None

        return res

    except Exception as e:
        TX_STATE = None



