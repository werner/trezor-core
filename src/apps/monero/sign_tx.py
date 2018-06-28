#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import gc
import micropython
from trezor import log


TX_STATE = None


async def layout_sign_tx(ctx, msg):
    log.debug(__name__, '### Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))

    from trezor.messages.MoneroRespError import MoneroRespError
    from apps.monero.protocol.tsx_sign import TsxSigner

    log.debug(__name__, '### Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))

    global TX_STATE

    log.debug(__name__, '\n\n\ntxsign: %s', TX_STATE)

    gc.collect()
    micropython.mem_info()
    micropython.mem_info(1)
    log.debug(__name__, '### Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))

    if TX_STATE is None or msg.init:
        TX_STATE = TsxSigner()

    try:
        res = await TX_STATE.sign(ctx, msg)
        if await TX_STATE.should_purge():
            TX_STATE = None

        return res

    except Exception as e:
        TX_STATE = None
        return MoneroRespError(exc=str(e))



