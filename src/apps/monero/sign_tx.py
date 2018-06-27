#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


from trezor.messages.MoneroTsxSign import MoneroTsxSign


TX_STATE = None


async def layout_sign_tx(ctx, msg: MoneroTsxSign):
    from apps.monero.protocol.tsx_sign import TsxSigner
    global TX_STATE

    if TX_STATE is None or msg.init:
        TX_STATE = TsxSigner()

    try:
        res = await TX_STATE.sign(ctx, msg)
        if await TX_STATE.should_purge():
            TX_STATE = None

        return res

    except Exception as e:
        TX_STATE = None



