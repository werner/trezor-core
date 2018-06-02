#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018
#
# Resources:
# https://cr.yp.to
# https://github.com/monero-project/mininero
# https://godoc.org/github.com/agl/ed25519/edwards25519
# https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-00#section-4
# https://github.com/monero-project/research-lab

import sys
import operator
import binascii

from .pycompat import *

# py constants
b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
d = -0x98412dfc9311d490018c7338bf8688861767ff8ff5b2bebe27548a14b235ec8feda4  # -121665 * inv(121666) % q

py_b = b
py_q = q
py_l = l
py_d = d


NULL_KEY_ENC = [0]*32

