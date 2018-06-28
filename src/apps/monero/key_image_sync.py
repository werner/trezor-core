#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import gc
import micropython
from trezor import log


SYNC_STATE = None


async def layout_key_image_sync(ctx, msg):
    log.debug(__name__, '### Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))

    log.debug(__name__, 'ki_sync')

    global SYNC_STATE
    log.debug(__name__, 'ki_sync: %s', SYNC_STATE)

    gc.collect()
    micropython.mem_info()
    micropython.mem_info(1)
    log.debug(__name__, '### 1Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))
    from apps.monero.protocol import key_image_sync
    log.debug(__name__, '### 8Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))

    log.debug(__name__, 'ki_sync import done')

    global SYNC_STATE
    try:
        if msg.init:
            log.debug(__name__, 'ki_sync, init')
            from apps.monero.controller import iface
            SYNC_STATE = key_image_sync.KeyImageSync(ctx=ctx, iface=iface.get_iface(ctx))
            return await SYNC_STATE.init(ctx, msg.init)

        elif msg.step:
            log.debug(__name__, 'ki_sync, step')
            return await SYNC_STATE.sync(ctx, msg.step)

        elif msg.final_msg:
            log.debug(__name__, 'ki_sync, final')
            res = await SYNC_STATE.final(ctx, msg.final_msg)
            SYNC_STATE = None
            return res

        else:
            raise ValueError('Unknown error')

    except Exception as e:
        from trezor.messages.MoneroRespError import MoneroRespError
        SYNC_STATE = None
        return MoneroRespError(exc=str(e))



