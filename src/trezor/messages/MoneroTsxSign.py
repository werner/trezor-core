# Automatically generated by pb2py
# fmt: off
import protobuf as p
from .MoneroTsxAllOutSet import MoneroTsxAllOutSet
from .MoneroTsxFinal import MoneroTsxFinal
from .MoneroTsxInit import MoneroTsxInit
from .MoneroTsxInputVini import MoneroTsxInputVini
from .MoneroTsxInputsPermutation import MoneroTsxInputsPermutation
from .MoneroTsxMlsagDone import MoneroTsxMlsagDone
from .MoneroTsxSetInput import MoneroTsxSetInput
from .MoneroTsxSetOutput import MoneroTsxSetOutput
from .MoneroTsxSignInput import MoneroTsxSignInput


class MoneroTsxSign(p.MessageType):
    MESSAGE_WIRE_TYPE = 301
    FIELDS = {
        1: ('init', MoneroTsxInit, 0),
        2: ('set_input', MoneroTsxSetInput, 0),
        3: ('input_permutation', MoneroTsxInputsPermutation, 0),
        4: ('input_vini', MoneroTsxInputVini, 0),
        5: ('set_output', MoneroTsxSetOutput, 0),
        6: ('all_out_set', MoneroTsxAllOutSet, 0),
        7: ('mlsag_done', MoneroTsxMlsagDone, 0),
        8: ('sign_input', MoneroTsxSignInput, 0),
        9: ('final_msg', MoneroTsxFinal, 0),
    }

    def __init__(
        self,
        init: MoneroTsxInit = None,
        set_input: MoneroTsxSetInput = None,
        input_permutation: MoneroTsxInputsPermutation = None,
        input_vini: MoneroTsxInputVini = None,
        set_output: MoneroTsxSetOutput = None,
        all_out_set: MoneroTsxAllOutSet = None,
        mlsag_done: MoneroTsxMlsagDone = None,
        sign_input: MoneroTsxSignInput = None,
        final_msg: MoneroTsxFinal = None,
    ) -> None:
        self.init = init
        self.set_input = set_input
        self.input_permutation = input_permutation
        self.input_vini = input_vini
        self.set_output = set_output
        self.all_out_set = all_out_set
        self.mlsag_done = mlsag_done
        self.sign_input = sign_input
        self.final_msg = final_msg
