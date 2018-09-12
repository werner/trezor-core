import gc

from trezor import log
from trezor.messages import MessageType


async def key_image_sync(ctx, msg):
    state = None

    while True:
        res, state = await key_image_sync_step(ctx, msg, state)
        if msg.final_msg:
            break
        msg = await ctx.call(res, MessageType.MoneroKeyImageSyncRequest)

    return res


async def key_image_sync_step(ctx, msg, state):
    if __debug__:
        log.debug(__name__, "f: %s a: %s", gc.mem_free(), gc.mem_alloc())
        log.debug(__name__, "s: %s", state)

    from apps.monero.protocol import key_image_sync

    if __debug__:
        log.debug(__name__, "f: %s a: %s", gc.mem_free(), gc.mem_alloc())
    gc.collect()

    if msg.init:
        from apps.monero.controller import iface

        state = key_image_sync.KeyImageSync(ctx=ctx, iface=iface.get_iface(ctx))
        return await state.init(ctx, msg.init), state

    elif msg.step:
        return await state.sync(ctx, msg.step), state

    elif msg.final_msg:
        return await state.final(ctx, msg.final_msg), None

    else:
        raise ValueError("Unknown error")
