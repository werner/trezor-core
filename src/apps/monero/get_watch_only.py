from apps.monero.xmr import trezor
from apps.monero.xmr import crypto
from apps.monero import layout
from trezor.messages.MoneroWatchKey import MoneroWatchKey


async def layout_monero_get_watch_only(ctx, msg):
    address_n = msg.address_n or ()
    creds = await trezor.monero_get_creds(ctx, address_n, msg.network_type)
    await layout.require_confirm_watchkey(ctx)
    return MoneroWatchKey(watch_key=crypto.encodeint(creds.view_key_private))



