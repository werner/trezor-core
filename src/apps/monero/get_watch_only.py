from apps.monero.controller import wrapper
from apps.monero.xmr import crypto
from apps.monero import layout

from trezor.messages.MoneroGetWatchKey import MoneroGetWatchKey
from trezor.messages.MoneroWatchKey import MoneroWatchKey

import gc
import micropython
from trezor import log


async def layout_monero_get_watch_only(ctx, msg: MoneroGetWatchKey):
    address_n = msg.address_n or ()
    log.debug(__name__, '12')
    await layout.require_confirm_watchkey(ctx)
    log.debug(__name__, '123')
    creds = await wrapper.monero_get_creds(ctx, address_n, msg.network_type)
    log.debug(__name__, '1234')
    return MoneroWatchKey(watch_key=crypto.encodeint(creds.view_key_private), address=creds.address)



