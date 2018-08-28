from trezor import wire
from trezor.messages import MessageType


# persistent state objects
class Holder(object):
    def __init__(self):
        self.ctx_sign = None
        self.ctx_ki = None
        self.ctx_lite = None


STATE = Holder()


def dispatch_MoneroTsxSign(*args, **kwargs):
    from apps.monero.sign_tx import layout_sign_tx

    return layout_sign_tx(STATE, *args, **kwargs)


def dispatch_MoneroKeyImageSync(*args, **kwargs):
    from apps.monero.key_image_sync import layout_key_image_sync

    return layout_key_image_sync(STATE, *args, **kwargs)


def dispatch_MoneroLiteInitRequest(*args, **kwargs):
    from apps.monero.lite_protocol import layout_lite_init_protocol

    return layout_lite_init_protocol(STATE, *args, **kwargs)


def dispatch_MoneroLiteRequest(*args, **kwargs):
    from apps.monero.lite_protocol import layout_lite_protocol

    return layout_lite_protocol(STATE, *args, **kwargs)


def add_stfl(msg_type, handler):
    wire.register(msg_type, wire.protobuf_workflow, handler)


def boot():
    wire.add(MessageType.MoneroGetAddress, __name__, "get_address")
    wire.add(MessageType.MoneroGetWatchKey, __name__, "get_watch_only")
    add_stfl(MessageType.MoneroTransactionSignRequest, dispatch_MoneroTsxSign)
    add_stfl(MessageType.MoneroKeyImageSyncRequest, dispatch_MoneroKeyImageSync)

    if hasattr(MessageType, "MoneroLiteInitRequest"):
        add_stfl(MessageType.MoneroLiteInitRequest, dispatch_MoneroLiteInitRequest)
        add_stfl(MessageType.MoneroLiteRequest, dispatch_MoneroLiteRequest)

    if hasattr(MessageType, "DebugMoneroDiagRequest"):
        wire.add(MessageType.DebugMoneroDiagRequest, __name__, "diag")
