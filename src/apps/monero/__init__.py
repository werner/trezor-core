from trezor.wire import register, protobuf_workflow
from trezor.messages.wire_types import \
    MoneroGetAddress, MoneroGetWatchKey, MoneroTsxSign, MoneroKeyImageSync


def dispatch_MoneroGetAddress(*args, **kwargs):
    from .get_address import layout_monero_get_address
    return layout_monero_get_address(*args, **kwargs)


def dispatch_MoneroGetWatchKey(*args, **kwargs):
    from .get_watch_only import layout_monero_get_watch_only
    return layout_monero_get_watch_only(*args, **kwargs)


def dispatch_MoneroTsxSign(*args, **kwargs):
    pass
    # from .sign_tx import lisk_sign_tx
    # return lisk_sign_tx(*args, **kwargs)


def dispatch_MoneroKeyImageSync(*args, **kwargs):
    pass
    # from .sign_tx import lisk_sign_tx
    # return lisk_sign_tx(*args, **kwargs)


def boot():
    register(MoneroGetAddress, protobuf_workflow, dispatch_MoneroGetAddress)
    register(MoneroGetWatchKey, protobuf_workflow, dispatch_MoneroGetWatchKey)
    register(MoneroTsxSign, protobuf_workflow, dispatch_MoneroTsxSign)
    register(MoneroKeyImageSync, protobuf_workflow, dispatch_MoneroKeyImageSync)
