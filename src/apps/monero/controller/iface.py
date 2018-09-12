class TrezorInterface(object):
    def __init__(self, ctx=None):
        self.ctx = ctx

    def gctx(self, ctx):
        return ctx if ctx is not None else self.ctx

    async def restore_default(self):
        from trezor import workflow

        workflow.restartdefault()

    async def confirm_out(
        self, dst, is_change=False, creds=None, int_payment=None, ctx=None
    ):
        """
        Single transaction destination confirmation
        """
        from apps.monero.xmr.sub.addr import encode_addr
        from apps.monero.xmr.sub.xmr_net import net_version
        from apps.monero import layout

        ver = net_version(
            creds.network_type, dst.is_subaddress, int_payment is not None
        )
        addr = encode_addr(
            ver, dst.addr.spend_public_key, dst.addr.view_public_key, int_payment
        )

        await layout.require_confirm_tx(
            self.gctx(ctx), addr.decode("ascii"), dst.amount, is_change
        )

    async def confirm_payment_id(self, payment_id, ctx=None):
        """
        Confirm payment ID
        """
        if payment_id is None:
            return

        from apps.monero import layout

        await layout.require_confirm_payment_id(self.gctx(ctx), payment_id)

    async def confirm_transaction(self, tsx_data, creds=None, ctx=None):
        """
        Ask for confirmation from user
        """
        from apps.monero.xmr.sub.addr import get_change_addr_idx

        outs = tsx_data.outputs
        change_idx = get_change_addr_idx(outs, tsx_data.change_dts)

        from apps.monero import layout

        has_integrated = (
            tsx_data.integrated_indices is not None
            and len(tsx_data.integrated_indices) > 0
        )
        has_payment = tsx_data.payment_id is not None and len(tsx_data.payment_id) > 0

        for idx, dst in enumerate(outs):
            is_change = change_idx is not None and idx == change_idx
            if is_change:
                continue
            if change_idx is None and dst.amount == 0 and len(outs) == 2:
                continue  # sweep, dummy tsx

            cur_payment = (
                tsx_data.payment_id
                if has_integrated and idx in tsx_data.integrated_indices
                else None
            )
            await self.confirm_out(dst, is_change, creds, cur_payment, ctx)

        if has_payment and not has_integrated:
            await self.confirm_payment_id(tsx_data.payment_id, ctx)

        await layout.require_confirm_fee(self.gctx(ctx), tsx_data.fee)

        from trezor.ui.text import Text
        from trezor import ui
        from trezor import loop
        from trezor import log
        from trezor import workflow
        from trezor.ui import BACKLIGHT_DIM, BACKLIGHT_NORMAL

        await ui.backlight_slide(BACKLIGHT_DIM)
        slide = ui.backlight_slide(BACKLIGHT_NORMAL)

        text = Text("Signing transaction", ui.ICON_SEND, icon_color=ui.BLUE)
        text.normal("Signing...")

        layout = await layout.simple_text(text, tm=500)
        workflow.closedefault()
        workflow.onlayoutstart(layout)
        loop.schedule(slide)

        await loop.sleep(200 * 1000)
        return True

    async def transaction_error(self, *args, **kwargs):
        from trezor import ui
        from trezor.ui.text import Text
        from apps.monero import layout

        text = Text("Error", ui.ICON_SEND, icon_color=ui.RED)
        text.normal("Transaction failed")

        await layout.ui_text(text, tm=500 * 1000)
        await self.restore_default()

    async def transaction_signed(self, ctx=None):
        """
        Notifies the transaction was completely signed
        """

    async def transaction_finished(self, ctx=None):
        """
        Notifies the transaction has been completed (all data were sent)
        """
        from trezor import ui
        from trezor.ui.text import Text
        from apps.monero import layout

        text = Text("Success", ui.ICON_SEND, icon_color=ui.GREEN)
        text.normal("Transaction signed")

        await layout.ui_text(text, tm=500 * 1000)
        await self.restore_default()

    async def transaction_step(self, step, sub_step=None, sub_step_total=None):
        from trezor import ui
        from trezor.ui.text import Text
        from apps.monero import layout

        info = []
        if step == 100:
            info = ["Processing inputs", "%d/%d" % (sub_step + 1, sub_step_total)]
        elif step == 200:
            info = ["Sorting"]
        elif step == 300:
            info = [
                "Processing inputs",
                "phase 2",
                "%d/%d" % (sub_step + 1, sub_step_total),
            ]
        elif step == 400:
            info = ["Processing outputs", "%d/%d" % (sub_step + 1, sub_step_total)]
        elif step == 500:
            info = ["Postprocessing..."]
        elif step == 600:
            info = ["Postprocessing..."]
        elif step == 700:
            info = ["Signing inputs", "%d/%d" % (sub_step + 1, sub_step_total)]
        else:
            info = ["Processing..."]

        text = Text("Signing transaction", ui.ICON_SEND, icon_color=ui.BLUE)
        text.normal(*info)

        await layout.simple_text(text, tm=10 * 1000)

    async def confirm_ki_sync(self, init_msg, ctx=None):
        from apps.monero import layout

        await layout.require_confirm_keyimage_sync(self.gctx(ctx))
        return True

    async def ki_error(self, e, ctx=None):
        pass

    async def ki_step(self, i, ctx=None):
        pass

    async def ki_finished(self, ctx=None):
        pass


def get_iface(ctx=None):
    return TrezorInterface(ctx)
