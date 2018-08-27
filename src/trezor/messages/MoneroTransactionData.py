# Automatically generated by pb2py
# fmt: off
import protobuf as p

from .MoneroTransactionDestinationEntry import MoneroTransactionDestinationEntry
from .MoneroTransactionRsigData import MoneroTransactionRsigData

if __debug__:
    try:
        from typing import List
    except ImportError:
        List = None  # type: ignore


class MoneroTransactionData(p.MessageType):
    FIELDS = {
        1: ('version', p.UVarintType, 0),
        2: ('payment_id', p.BytesType, 0),
        3: ('unlock_time', p.UVarintType, 0),
        4: ('outputs', MoneroTransactionDestinationEntry, p.FLAG_REPEATED),
        5: ('change_dts', MoneroTransactionDestinationEntry, 0),
        6: ('num_inputs', p.UVarintType, 0),
        7: ('mixin', p.UVarintType, 0),
        8: ('fee', p.UVarintType, 0),
        9: ('account', p.UVarintType, 0),
        10: ('minor_indices', p.UVarintType, p.FLAG_REPEATED),
        11: ('is_multisig', p.BoolType, 0),
        12: ('exp_tx_prefix_hash', p.BytesType, 0),
        13: ('use_tx_keys', p.BytesType, p.FLAG_REPEATED),
        14: ('rsig_data', MoneroTransactionRsigData, 0),
    }

    def __init__(
        self,
        version: int = None,
        payment_id: bytes = None,
        unlock_time: int = None,
        outputs: List[MoneroTransactionDestinationEntry] = None,
        change_dts: MoneroTransactionDestinationEntry = None,
        num_inputs: int = None,
        mixin: int = None,
        fee: int = None,
        account: int = None,
        minor_indices: List[int] = None,
        is_multisig: bool = None,
        exp_tx_prefix_hash: bytes = None,
        use_tx_keys: List[bytes] = None,
        rsig_data: MoneroTransactionRsigData = None,
    ) -> None:
        self.version = version
        self.payment_id = payment_id
        self.unlock_time = unlock_time
        self.outputs = outputs if outputs is not None else []
        self.change_dts = change_dts
        self.num_inputs = num_inputs
        self.mixin = mixin
        self.fee = fee
        self.account = account
        self.minor_indices = minor_indices if minor_indices is not None else []
        self.is_multisig = is_multisig
        self.exp_tx_prefix_hash = exp_tx_prefix_hash
        self.use_tx_keys = use_tx_keys if use_tx_keys is not None else []
        self.rsig_data = rsig_data
