# Automatically generated by pb2py
import protobuf as p


class MoneroKeyImageSyncFinalResp(p.MessageType):
    MESSAGE_WIRE_TYPE = 324
    FIELDS = {
        1: ('enc_key', p.BytesType, 0),
    }

    def __init__(
        self,
        enc_key: bytes = None
    ) -> None:
        self.enc_key = enc_key
