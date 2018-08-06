import gc

from trezor import log, utils
from trezor.messages import MessageType


async def sign_tx(ctx, msg):
    state = None
    gc.collect()
    mods = utils.unimport_begin()

    while True:
        if __debug__:
            log.debug(__name__, "#### F: %s, A: %s", gc.mem_free(), gc.mem_alloc())
        res, state, accept_msgs = await sign_tx_step(ctx, msg, state)
        if accept_msgs is None:
            break

        await ctx.write(res)
        del (res, msg)
        utils.unimport_end(mods)

        msg = await ctx.read(accept_msgs)
        gc.collect()

    utils.unimport_end(mods)
    return res


async def sign_tx_step(ctx, msg, state):
    gc.threshold(gc.mem_free() // 4 + gc.mem_alloc())
    gc.collect()

    from apps.monero.controller import iface, wrapper
    from apps.monero.protocol.tsx_sign_builder import TTransactionBuilder

    if msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionInitRequest:
        creds = await wrapper.monero_get_creds(ctx, msg.address_n, msg.network_type)
        state = TTransactionBuilder(iface.get_iface(ctx), creds)
        del creds

    gc.collect()
    res, accept_msgs = await sign_tx_dispatch(state, msg)
    gc.collect()

    if state.is_terminal():
        state = None
    return res, state, accept_msgs


async def sign_tx_dispatch(tsx, msg):
    if msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionInitRequest:
        return (
            await tsx_init(tsx, msg.tsx_data),
            (MessageType.MoneroTransactionSetInputRequest,),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionSetInputRequest:
        return (
            await tsx_set_input(tsx, msg),
            (
                MessageType.MoneroTransactionSetInputRequest,
                MessageType.MoneroTransactionInputsPermutationRequest,
            ),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionInputsPermutationRequest:
        return (
            await tsx_inputs_permutation(tsx, msg),
            (MessageType.MoneroTransactionInputViniRequest,),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionInputViniRequest:
        return (
            await tsx_input_vini(tsx, msg),
            (
                MessageType.MoneroTransactionInputViniRequest,
                MessageType.MoneroTransactionAllInputsSetRequest,
            ),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionAllInputsSetRequest:
        return (
            await tsx_all_in_set(tsx, msg),
            (MessageType.MoneroTransactionSetOutputRequest,),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionSetOutputRequest:
        return (
            await tsx_set_output1(tsx, msg),
            (
                MessageType.MoneroTransactionSetOutputRequest,
                MessageType.MoneroTransactionAllOutSetRequest,
            ),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionAllOutSetRequest:
        return (
            await tsx_all_out1_set(tsx, msg),
            (MessageType.MoneroTransactionMlsagDoneRequest,),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionMlsagDoneRequest:
        return (
            await tsx_mlsag_done(tsx),
            (MessageType.MoneroTransactionSignInputRequest,),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionSignInputRequest:
        return (
            await tsx_sign_input(tsx, msg),
            (
                MessageType.MoneroTransactionSignInputRequest,
                MessageType.MoneroTransactionFinalRequest,
            ),
        )

    elif msg.MESSAGE_WIRE_TYPE == MessageType.MoneroTransactionFinalRequest:
        return await tsx_sign_final(tsx), None

    else:
        from trezor import wire

        raise wire.DataError("Unknown message")


async def tsx_init(tsx, tsx_data):
    return await tsx.init_transaction(tsx_data)


async def tsx_set_input(tsx, msg):
    """
    Sets UTXO one by one.
    Computes spending secret key, key image. tx.vin[i] + HMAC, Pedersen commitment on amount.

    If number of inputs is small, in-memory mode is used = alpha, pseudo_outs are kept in the Trezor.
    Otherwise pseudo_outs are offloaded with HMAC, alpha is offloaded encrypted under AES-GCM() with
    key derived for exactly this purpose.
    """
    return await tsx.set_input(msg.src_entr)


async def tsx_inputs_permutation(tsx, msg):
    """
    Set permutation on the inputs - sorted by key image on host.
    """
    return await tsx.tsx_inputs_permutation(msg.perm)


async def tsx_input_vini(tsx, msg):
    """
    Set tx.vin[i] for incremental tx prefix hash computation.
    After sorting by key images on host.
    """
    return await tsx.input_vini(
        msg.src_entr, msg.vini, msg.vini_hmac, msg.pseudo_out, msg.pseudo_out_hmac
    )


async def tsx_all_in_set(tsx, msg):
    """
    All inputs set. Defining rsig parameters.
    """
    return await tsx.all_in_set(msg.rsig_data)


async def tsx_set_output1(tsx, msg):
    """
    Set destination entry one by one.
    Computes destination stealth address, amount key, range proof + HMAC, out_pk, ecdh_info.
    """
    dst, dst_hmac, rsig_data = msg.dst_entr, msg.dst_entr_hmac, msg.rsig_data
    del (msg)

    return await tsx.set_out1(dst, dst_hmac, rsig_data)


async def tsx_all_out1_set(tsx, msg):
    """
    All outputs were set in this phase. Computes additional public keys (if needed), tx.extra and
    transaction prefix hash.
    Adds additional public keys to the tx.extra

    :return: tx.extra, tx_prefix_hash
    """
    from apps.monero.controller.misc import TrezorTxPrefixHashNotMatchingError

    try:
        return await tsx.all_out1_set()
    except TrezorTxPrefixHashNotMatchingError as e:
        from trezor import wire

        raise wire.NotEnoughFunds(e.message)


async def tsx_mlsag_done(tsx):
    """
    MLSAG message computed.
    """
    return await tsx.mlsag_done()


async def tsx_sign_input(tsx, msg):
    """
    Generates a signature for one input.
    """
    return await tsx.sign_input(
        msg.src_entr,
        msg.vini,
        msg.vini_hmac,
        msg.pseudo_out,
        msg.pseudo_out_hmac,
        msg.alpha_enc,
        msg.spend_enc,
    )


async def tsx_sign_final(tsx):
    """
    Final message.
    Offloading tx related data, encrypted.
    """
    return await tsx.final_msg()
