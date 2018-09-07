import gc
import micropython

from trezor import log


async def key_image_sync(ctx, msg, state):
    log.debug(
        __name__,
        "### KI SYNC. Free: {} Allocated: {}".format(gc.mem_free(), gc.mem_alloc()),
    )
    log.debug(__name__, "KI sync state: %s", state.ctx_ki)

    from apps.monero.protocol import key_image_sync

    log.debug(
        __name__,
        "### KI sync imported. Free: {} Allocated: {}".format(
            gc.mem_free(), gc.mem_alloc()
        ),
    )

    gc.collect()
    micropython.mem_info()
    micropython.mem_info(1)

    try:
        if msg.init:
            log.debug(__name__, "ki_sync, init")
            from apps.monero.controller import iface

            state.ctx_ki = key_image_sync.KeyImageSync(
                ctx=ctx, iface=iface.get_iface(ctx)
            )
            return await state.ctx_ki.init(ctx, msg.init)

        elif msg.step:
            log.debug(__name__, "ki_sync, step")
            return await state.ctx_ki.sync(ctx, msg.step)

        elif msg.final_msg:
            log.debug(__name__, "ki_sync, final")
            res = await state.ctx_ki.final(ctx, msg.final_msg)
            state.ctx_ki = None
            return res

        else:
            raise ValueError("Unknown error")

    except Exception as e:
        state.ctx_ki = None

        log.debug(__name__, "KI error, %s: %s", type(e), e)
        raise
        # from trezor.messages.Failure import Failure

        # return Failure()
