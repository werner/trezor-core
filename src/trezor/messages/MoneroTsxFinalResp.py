# Automatically generated by pb2py
# fmt: off
import protobuf as p


class MoneroTsxFinalResp(p.MessageType):
    MESSAGE_WIRE_TYPE = 310
    FIELDS = {
        1: ('cout_key', p.BytesType, 0),
        2: ('salt', p.BytesType, 0),
        3: ('rand_mult', p.BytesType, 0),
        4: ('tx_enc_keys', p.BytesType, 0),
    }

    def __init__(
        self,
        cout_key: bytes = None,
        salt: bytes = None,
        rand_mult: bytes = None,
        tx_enc_keys: bytes = None,
    ) -> None:
        self.cout_key = cout_key
        self.salt = salt
        self.rand_mult = rand_mult
        self.tx_enc_keys = tx_enc_keys
