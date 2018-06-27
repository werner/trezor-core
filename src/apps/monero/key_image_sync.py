#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from apps.monero.messages import MoneroKeyImageSync, MoneroRespError

SYNC_STATE = None


async def layout_key_image_sync(ctx, msg: MoneroKeyImageSync):
    from apps.monero.protocol import key_image_sync
    from apps.monero.controller import iface

    global SYNC_STATE
    try:
        print('msgin')
        if msg.init:
            print('init')
            SYNC_STATE = key_image_sync.KeyImageSync(ctx=ctx, iface=iface.get_iface(ctx))
            return await SYNC_STATE.init(ctx, msg.init)

        elif msg.step:
            print('step')
            print(SYNC_STATE)
            return await SYNC_STATE.sync(ctx, msg.step)

        elif msg.final_msg:
            print('final')
            res = await SYNC_STATE.final(ctx, msg.final_msg)
            SYNC_STATE = None
            return res

        else:
            raise ValueError('Unknown error')

    except Exception as e:
        SYNC_STATE = None
        return MoneroRespError(exc=str(e))



