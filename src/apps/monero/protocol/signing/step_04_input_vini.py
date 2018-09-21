import gc

from .tsx_sign_builder import TransactionSigningState

from apps.monero.controller import misc
from apps.monero.xmr import common, crypto, monero


async def input_vini(self, src_entr, vini_bin, hmac, pseudo_out, pseudo_out_hmac):
    """
    Set tx.vin[i] for incremental tx prefix hash computation.
    After sorting by key images on host.
    Hashes pseudo_out to the final_message.
    """
    from trezor.messages.MoneroTransactionInputViniAck import (
        MoneroTransactionInputViniAck
    )

    await self.iface.transaction_step(
        self.STEP_VINI, self.inp_idx + 1, self.num_inputs()
    )

    if self.inp_idx >= self.num_inputs():
        raise ValueError("Too many inputs")

    self.state.input_vins()
    self.inp_idx += 1

    # HMAC(T_in,i || vin_i)
    hmac_vini = await self.gen_hmac_vini(
        src_entr, vini_bin, self.source_permutation[self.inp_idx]
    )
    if not common.ct_equal(hmac_vini, hmac):
        raise ValueError("HMAC is not correct")

    self.hash_vini_pseudo_out(vini_bin, self.inp_idx, pseudo_out, pseudo_out_hmac)
    return MoneroTransactionInputViniAck()


def hash_vini_pseudo_out(
    self, vini_bin, inp_idx, pseudo_out=None, pseudo_out_hmac=None
):
    """
    Incremental hasing of tx.vin[i] and pseudo output
    """
    self.tx_prefix_hasher.buffer(vini_bin)

    # Pseudo_out incremental hashing - applicable only in simple rct
    if not self.use_simple_rct or self.use_bulletproof:
        return

    idx = self.source_permutation[inp_idx]
    pseudo_out_hmac_comp = crypto.compute_hmac(self.hmac_key_txin_comm(idx), pseudo_out)
    if not common.ct_equal(pseudo_out_hmac, pseudo_out_hmac_comp):
        raise ValueError("HMAC invalid for pseudo outs")

    self.full_message_hasher.set_pseudo_out(pseudo_out)
