# Automatically generated by pb2py
import protobuf as p


class MoneroTsxSetInput(p.MessageType):
    MESSAGE_WIRE_TYPE = 303
    FIELDS = {
        1: ('version', p.UVarintType, 0),
        2: ('src_entr', p.BytesType, 0),
    }

    def __init__(
        self,
        version: int = None,
        src_entr: bytes = None
    ) -> None:
        self.version = version
        self.src_entr = src_entr
