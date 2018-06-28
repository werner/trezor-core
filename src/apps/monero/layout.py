from apps.common.confirm import confirm, require_confirm, require_hold_to_confirm
from apps.wallet.get_public_key import _show_pubkey
from trezor import ui
from trezor.messages import ButtonRequestType
from trezor.ui.text import Text
from trezor.utils import chunks


async def require_confirm_watchkey(ctx):
    content = Text('Confirm watch-only', ui.ICON_SEND,
                   'Do you really want to',
                   'return a watch-only?',
                   ui.BOLD,
                   icon_color=ui.GREEN)
    return await require_confirm(ctx, content, ButtonRequestType.SignTx)


async def require_confirm_keys(ctx):
    content = Text('Confirm export', ui.ICON_SEND,
                   'Do you really want to',
                   'export wallet keys?',
                   ui.BOLD,
                   icon_color=ui.RED)
    return await require_confirm(ctx, content, ButtonRequestType.SignTx)


async def require_confirm_keyimage_sync(ctx):
    content = Text('Confirm ki sync', ui.ICON_SEND,
                   'Do you really want to',
                   'sync key images?',
                   ui.BOLD,
                   icon_color=ui.GREEN)
    return await require_confirm(ctx, content, ButtonRequestType.SignTx)


async def require_confirm_tx_plain(ctx, to, value):
    content = Text('Confirm sending', ui.ICON_SEND,
                   ui.BOLD, format_amount(value),
                   ui.NORMAL, 'to',
                   ui.MONO, *split_address(to),
                   icon_color=ui.GREEN)
    return await require_confirm(ctx, content, code=ButtonRequestType.SignTx)


@ui.layout
async def tx_dialog(ctx, code, content, cancel_btn, confirm_btn, cancel_style, confirm_style):
    from trezor.messages import wire_types
    from trezor.messages.ButtonRequest import ButtonRequest
    from trezor.ui.confirm import ConfirmDialog

    await ctx.call(ButtonRequest(code=code), wire_types.ButtonAck)
    dialog = ConfirmDialog(content, cancel=cancel_btn, confirm=confirm_btn,
                           cancel_style=cancel_style, confirm_style=confirm_style)
    return await ctx.wait(dialog)


async def require_confirm_tx(ctx, to, value):
    len_addr = (len(to) + 15) // 16
    if len_addr <= 2:
        return await require_confirm_tx_plain(ctx, to, value)

    else:
        to_chunks = list(split_address(to))
        from trezor import res, wire
        from trezor.messages import wire_types
        from trezor.messages.ButtonRequest import ButtonRequest
        from trezor.ui.confirm import CONFIRMED, CANCELLED, ConfirmDialog, DEFAULT_CANCEL, DEFAULT_CONFIRM

        npages = 1 + ((len_addr - 2) + 3) // 4
        cur_step = 0
        code = ButtonRequestType.SignTx
        iback = res.load(ui.ICON_BACK)
        inext = res.load(ui.ICON_CLICK)

        while cur_step <= npages:
            text = []
            if cur_step == 0:
                text = [ui.BOLD, format_amount(value),
                        ui.NORMAL, 'to',
                        ui.MONO, ] + to_chunks[:2]
            else:
                off = 4*(cur_step - 1)
                cur_chunks = to_chunks[2+off:2+off+4]
                ctext = [list(x) for x in zip([ui.MONO]*len(cur_chunks), cur_chunks)]
                for x in ctext:
                    text += x

            if cur_step == 0:
                cancel_btn = DEFAULT_CANCEL
                cancel_style = ui.BTN_CANCEL
                confirm_btn = inext
                confirm_style = ui.BTN_DEFAULT
            elif cur_step + 1 < npages:
                cancel_btn = iback
                cancel_style = ui.BTN_DEFAULT
                confirm_btn = inext
                confirm_style = ui.BTN_DEFAULT
            else:
                cancel_btn = iback
                cancel_style = ui.BTN_DEFAULT
                confirm_btn = DEFAULT_CONFIRM
                confirm_style = ui.BTN_CONFIRM

            content = Text('Confirm send %d/%d' % (cur_step+1, npages), ui.ICON_SEND,
                           *text,
                           icon_color=ui.GREEN)

            reaction = await tx_dialog(ctx, code, content, cancel_btn, confirm_btn, cancel_style, confirm_style)

            if cur_step == 0 and reaction == CANCELLED:
                raise wire.ActionCancelled('Cancelled')
            elif cur_step + 1 < npages and reaction == CONFIRMED:
                cur_step += 1
            elif cur_step + 1 >= npages and reaction == CONFIRMED:
                return
            elif reaction == CANCELLED:
                cur_step -= 1
            elif reaction == CONFIRMED:
                cur_step += 1


async def require_confirm_public_key(ctx, public_key):
    return await _show_pubkey(ctx, public_key)


async def require_confirm_multisig(ctx, multisignature):
    content = Text('Confirm transaction', ui.ICON_SEND,
                   ('Keys group length: %s' % len(multisignature.keys_group)),
                   ('Life time: %s' % multisignature.life_time),
                   ('Min: %s' % multisignature.min),
                   icon_color=ui.GREEN)
    return await require_confirm(ctx, content, ButtonRequestType.SignTx)


async def require_confirm_fee(ctx, value, fee):
    content = Text('Confirm transaction', ui.ICON_SEND,
                   ui.BOLD, format_amount(value),
                   ui.NORMAL, 'fee:',
                   ui.BOLD, format_amount(fee),
                   icon_color=ui.GREEN)
    await require_hold_to_confirm(ctx, content, ButtonRequestType.ConfirmOutput)


def format_amount(value):
    return '%f XMR' % (value / 1000000000000)


def split_address(address):
    return chunks(address, 16)
