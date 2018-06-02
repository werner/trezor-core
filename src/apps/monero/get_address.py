from apps.monero.xmr import trezor
from apps.wallet.get_address import _show_address, _show_qr
from trezor.messages.MoneroAddress import MoneroAddress


async def layout_monero_get_address(ctx, msg):
    address_n = msg.address_n or ()
    creds = await trezor.monero_get_creds(ctx, address_n, msg.network_type)

    if msg.show_display:
        while True:
            if await _show_address(ctx, creds.address):
                break
            if await _show_qr(ctx, creds.address):
                break

    return MoneroAddress(address=creds.address.decode('ascii'))

