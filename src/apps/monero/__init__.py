from trezor import wire
from trezor.messages import MessageType


# persistent state objects
class Holder:
    def __init__(self):
        self.ctx_sign = None
        self.ctx_ki = None
        self.ctx_lite = None


STATE = Holder()


def boot():
    wire.add(MessageType.MoneroGetAddress, __name__, "get_address")
    wire.add(MessageType.MoneroGetWatchKey, __name__, "get_watch_only")
    wire.add(MessageType.MoneroTransactionInitRequest, __name__, "sign_tx")
    wire.add(MessageType.MoneroKeyImageExportInitRequest, __name__, "key_image_sync")

    if hasattr(MessageType, "MoneroLiteInitRequest"):
        wire.add(MessageType.MoneroLiteInitRequest, "lite_protocol", STATE, 1)
        wire.add(MessageType.MoneroLiteRequest, "lite_protocol", STATE, 0)

    if hasattr(MessageType, "DebugMoneroDiagRequest"):
        wire.add(MessageType.DebugMoneroDiagRequest, __name__, "diag")
