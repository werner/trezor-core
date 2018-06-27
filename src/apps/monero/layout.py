from apps.common.confirm import require_confirm, require_hold_to_confirm
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


async def require_confirm_tx(ctx, to, value):
    content = Text('Confirm sending', ui.ICON_SEND,
                   ui.BOLD, format_amount(value),
                   ui.NORMAL, 'to',
                   ui.MONO, *split_address(to),
                   icon_color=ui.GREEN)
    return await require_confirm(ctx, content, ButtonRequestType.SignTx)


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
