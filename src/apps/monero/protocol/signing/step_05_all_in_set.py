import gc

from .tsx_sign_builder import TransactionSigningState

from apps.monero.controller import misc
from apps.monero.xmr import common, crypto, monero


async def all_in_set(self, rsig_data):
    """
    If in the applicable offloading mode, generate commitment masks.
    """
    self._mem_trace(0)
    self.state.input_all_done()
    await self.iface.transaction_step(self.STEP_ALL_IN)

    from trezor.messages.MoneroTransactionAllInputsSetAck import (
        MoneroTransactionAllInputsSetAck
    )
    from trezor.messages.MoneroTransactionRsigData import MoneroTransactionRsigData

    rsig_data = MoneroTransactionRsigData()
    resp = MoneroTransactionAllInputsSetAck(rsig_data=rsig_data)

    if not self.rsig_offload:
        return resp

    # Simple offloading - generate random masks that sum to the input mask sum.
    tmp_buff = bytearray(32)
    rsig_data.mask = bytearray(32 * self.num_dests())
    self.sumout = crypto.sc_init(0)
    for i in range(self.num_dests()):
        cur_mask = crypto.new_scalar()
        is_last = i + 1 == self.num_dests()
        if is_last and self.use_simple_rct:
            crypto.sc_sub_into(cur_mask, self.sumpouts_alphas, self.sumout)
        else:
            crypto.random_scalar(cur_mask)

        crypto.sc_add_into(self.sumout, self.sumout, cur_mask)
        self.output_masks.append(cur_mask)
        crypto.encodeint_into(tmp_buff, cur_mask)
        utils.memcpy(rsig_data.mask, 32 * i, tmp_buff, 0, 32)

    self.assrt(crypto.sc_eq(self.sumout, self.sumpouts_alphas), "Invalid masks sum")
    self.sumout = crypto.sc_init(0)
    return resp
