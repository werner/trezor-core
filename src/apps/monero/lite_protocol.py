import gc

from trezor import log


async def lite_init_protocol(ctx, msg, state):
    from apps.monero.protocol_lite import lite
    from trezor.messages.MoneroLiteInitAck import MoneroLiteInitAck

    state.ctx_lite = lite.LiteProtocol()
    await state.ctx_lite.init(ctx, msg)
    return MoneroLiteInitAck()


async def lite_protocol(ctx, msg, state, is_init=False):
    if is_init:
        return await lite_init_protocol(ctx, msg, state)

    from trezor.messages.MoneroLiteAck import MoneroLiteAck

    if __debug__:
        log.debug(
            __name__,
            "### Lite. Free: {} Allocated: {}".format(gc.mem_free(), gc.mem_alloc()),
        )

    gc.collect()
    try:
        sw, buff = await state.ctx_lite.dispatch(ctx, msg.ins, msg.p1, msg.p2, msg.data)

        res = MoneroLiteAck(sw=sw, data=buff)
        return res

    except Exception as e:
        state.ctx_ki = None
        if __debug__:
            log.debug(__name__, "Lite error, %s: %s", type(e), e)
        raise
