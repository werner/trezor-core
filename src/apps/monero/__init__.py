from trezor.wire import register, protobuf_workflow
from trezor.messages.wire_types import \
    MoneroGetAddress, MoneroGetWatchKey, MoneroGetKey, MoneroTsxSign, MoneroKeyImageSync


import gc
import micropython
from trezor import log

# persistent state objects
from apps.monero.sign_tx import layout_sign_tx
from apps.monero.key_image_sync import layout_key_image_sync



def dispatch_MoneroGetAddress(*args, **kwargs):
    from apps.monero.get_address import layout_monero_get_address
    return layout_monero_get_address(*args, **kwargs)


def dispatch_MoneroGetWatchKey(*args, **kwargs):
    from apps.monero.get_watch_only import layout_monero_get_watch_only
    return layout_monero_get_watch_only(*args, **kwargs)


def dispatch_MoneroGetKey(*args, **kwargs):
    from .get_keys import layout_monero_get_keys
    return layout_monero_get_keys(*args, **kwargs)


def dispatch_MoneroTsxSign(*args, **kwargs):
    return layout_sign_tx(*args, **kwargs)


def dispatch_MoneroKeyImageSync(*args, **kwargs):
    return layout_key_image_sync(*args, **kwargs)


def boot():
    register(MoneroGetAddress, protobuf_workflow, dispatch_MoneroGetAddress)
    register(MoneroGetWatchKey, protobuf_workflow, dispatch_MoneroGetWatchKey)
    register(MoneroGetKey, protobuf_workflow, dispatch_MoneroGetKey)
    register(MoneroTsxSign, protobuf_workflow, dispatch_MoneroTsxSign)
    register(MoneroKeyImageSync, protobuf_workflow, dispatch_MoneroKeyImageSync)
