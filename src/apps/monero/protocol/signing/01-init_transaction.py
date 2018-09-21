import gc

from apps.monero.controller import misc
from apps.monero.xmr import common, crypto, monero

from .tsx_sign_builder import TransactionSigningState


async def init_transaction(state: TransactionSigningState, tsx_data):
    """
    Initializes a new transaction.
    """
    from apps.monero.xmr.sub.addr import classify_subaddresses

    gen_r(state)
    state.state.init_tsx()
    state._mem_trace(1)

    # Ask for confirmation
    await state.iface.confirm_transaction(tsx_data, state.creds)
    gc.collect()
    state._mem_trace(3)

    # Basic transaction parameters
    state.input_count = tsx_data.num_inputs
    state.output_count = len(tsx_data.outputs)
    state.output_change = misc.dst_entry_to_stdobj(tsx_data.change_dts)
    state.mixin = tsx_data.mixin
    state.fee = tsx_data.fee
    state.account_idx = tsx_data.account
    state.multi_sig = tsx_data.is_multisig
    state.state.inp_cnt()
    check_change(state, tsx_data.outputs)
    state.exp_tx_prefix_hash = common.defval_empty(tsx_data.exp_tx_prefix_hash, None)

    # Rsig data
    state.rsig_type = tsx_data.rsig_data.rsig_type
    state.rsig_grp = tsx_data.rsig_data.grouping
    state.rsig_offload = state.rsig_type > 0 and state.output_count > 2
    state.use_bulletproof = state.rsig_type > 0
    state.use_simple_rct = state.input_count > 1 or state.rsig_type != 0

    # Provided tx key, used mostly in multisig.
    if len(tsx_data.use_tx_keys) > 0:
        for ckey in tsx_data.use_tx_keys:
            crypto.check_sc(crypto.decodeint(ckey))

        state.gen_r(use_r=crypto.decodeint(tsx_data.use_tx_keys[0]))
        state.additional_tx_private_keys = [
            crypto.decodeint(x) for x in tsx_data.use_tx_keys[1:]
        ]

    # Additional keys w.r.t. subaddress destinations
    class_res = classify_subaddresses(tsx_data.outputs, state.change_address())
    num_stdaddresses, num_subaddresses, single_dest_subaddress = class_res

    # if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=r*D
    if num_stdaddresses == 0 and num_subaddresses == 1:
        state.r_pub = crypto.scalarmult(
            crypto.decodepoint(single_dest_subaddress.spend_public_key), state.r
        )

    state.need_additional_txkeys = num_subaddresses > 0 and (
        num_stdaddresses > 0 or num_subaddresses > 1
    )
    state._mem_trace(4, True)

    # Extra processing, payment id
    state.tx.version = 2
    state.tx.unlock_time = tsx_data.unlock_time
    process_payment_id(state, tsx_data)
    await compute_sec_keys(state, tsx_data)
    gc.collect()

    # Iterative tx_prefix_hash hash computation
    _tprefix_update()
    gc.collect()

    # Final message hasher
    state.full_message_hasher.init(state.use_simple_rct)
    state.full_message_hasher.set_type_fee(state.get_rct_type(), state.get_fee())

    # Sub address precomputation
    if tsx_data.account is not None and tsx_data.minor_indices:
        precompute_subaddr(state, tsx_data.account, tsx_data.minor_indices)
    state._mem_trace(5, True)

    # HMAC outputs - pinning
    hmacs = []
    for idx in range(state.num_dests()):
        c_hmac = await state.gen_hmac_tsxdest(tsx_data.outputs[idx], idx)
        hmacs.append(c_hmac)
        gc.collect()

    state._mem_trace(6)

    from trezor.messages.MoneroTransactionInitAck import MoneroTransactionInitAck
    from trezor.messages.MoneroTransactionRsigData import MoneroTransactionRsigData

    rsig_data = MoneroTransactionRsigData(offload_type=state.rsig_offload)
    return MoneroTransactionInitAck(
        in_memory=False,
        many_inputs=True,
        many_outputs=True,
        hmacs=hmacs,
        rsig_data=rsig_data,
    )


def gen_r(state, use_r=None):
    """
    Generates a new transaction key pair.
    """
    state.r = crypto.random_scalar() if use_r is None else use_r
    state.r_pub = crypto.scalarmult_base(state.r)


def get_primary_change_address(state: TransactionSigningState):
    """
    Computes primary change address for the current account index
    """
    D, C = monero.generate_sub_address_keys(
        state.creds.view_key_private,
        state.creds.spend_key_public,
        state.account_idx,
        0,
    )
    return misc.StdObj(
        view_public_key=crypto.encodepoint(C),
        spend_public_key=crypto.encodepoint(D),
    )


def check_change(state: TransactionSigningState, outputs):
    """
    Checks if the change address is among tx outputs and it is equal to our address.
    """
    from apps.monero.xmr.sub.addr import addr_eq, get_change_addr_idx

    change_idx = get_change_addr_idx(outputs, state.output_change)

    change_addr = state.change_address()
    if change_addr is None:
        state._mem_trace("No change" if __debug__ else None)
        return

    if change_idx is None and state.output_change.amount == 0 and len(outputs) == 2:
        state._mem_trace("Sweep tsx" if __debug__ else None)
        return  # sweep dummy tsx

    found = False
    for out in outputs:
        if addr_eq(out.addr, change_addr):
            found = True
            break

    if not found:
        raise misc.TrezorChangeAddressError("Change address not found in outputs")

    my_addr = get_primary_change_address(state)
    if not addr_eq(my_addr, change_addr):
        raise misc.TrezorChangeAddressError("Change address differs from ours")

    return True


def process_payment_id(state: TransactionSigningState, tsx_data):
    """
    Payment id -> extra
    """
    if common.is_empty(tsx_data.payment_id):
        return

    from apps.monero.xmr.sub import tsx_helper

    if len(tsx_data.payment_id) == 8:
        view_key_pub_enc = tsx_helper.get_destination_view_key_pub(
            tsx_data.outputs, state.change_address()
        )
        if view_key_pub_enc == crypto.NULL_KEY_ENC:
            raise ValueError(
                "Destinations have to have exactly one output to support encrypted payment ids"
            )

        view_key_pub = crypto.decodepoint(view_key_pub_enc)
        payment_id_encr = tsx_helper.encrypt_payment_id(
            tsx_data.payment_id, view_key_pub, self.r
        )

        extra_nonce = payment_id_encr
        extra_prefix = 1

    elif len(tsx_data.payment_id) == 32:
        extra_nonce = tsx_data.payment_id
        extra_prefix = 0

    else:
        raise ValueError("Payment ID size invalid")

    lextra = len(extra_nonce)
    if lextra >= 255:
        raise ValueError("Nonce could be 255 bytes max")

    extra_buff = bytearray(3 + lextra)
    extra_buff[0] = 2
    extra_buff[1] = lextra + 1
    extra_buff[2] = extra_prefix
    utils.memcpy(extra_buff, 3, extra_nonce, 0, lextra)
    state.tx.extra = extra_buff


async def compute_sec_keys(state: TransactionSigningState, tsx_data):
    """
    Generate master key H(TsxData || r)
    :return:
    """
    import protobuf
    from apps.monero.xmr.sub.keccak_hasher import get_keccak_writer

    writer = get_keccak_writer()
    await protobuf.dump_message(writer, tsx_data)
    writer.write(crypto.encodeint(state.r))

    state.key_master = crypto.keccak_2hash(
        writer.get_digest() + crypto.encodeint(crypto.random_scalar())
    )
    state.key_hmac = crypto.keccak_2hash(b"hmac" + self.key_master)
    state.key_enc = crypto.keccak_2hash(b"enc" + self.key_master)


def precompute_subaddr(state, account, indices):
    """
    Precomputes subaddresses for account (major) and list of indices (minors)
    Subaddresses have to be stored in encoded form - unique representation.
    Single point can have multiple extended coordinates representation - would not match during subaddress search.
    """
    monero.compute_subaddresses(state.creds, account, indices, state.subaddresses)


def _tprefix_update(state):
    state.tx_prefix_hasher.keep()
    state.tx_prefix_hasher.uvarint(state.tx.version)
    state.tx_prefix_hasher.uvarint(state.tx.unlock_time)
    state.tx_prefix_hasher.container_size(state.num_inputs())  # ContainerType
    state.tx_prefix_hasher.release()
    state._mem_trace(10, True)
