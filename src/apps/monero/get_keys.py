from apps.monero.controller import wrapper
from apps.monero.xmr import crypto
from apps.monero import layout
from apps.monero.messages import MoneroGetKey, MoneroKey


async def layout_monero_get_keys(ctx, msg: MoneroGetKey):
    address_n = msg.address_n or ()
    await layout.require_confirm_keys(ctx)
    creds = await wrapper.monero_get_creds(ctx, address_n, msg.network_type)
    return MoneroKey(watch_key=crypto.encodeint(creds.view_key_private),
                     spend_key=crypto.encodeint(creds.spend_key_private),
                     address=creds.address)



