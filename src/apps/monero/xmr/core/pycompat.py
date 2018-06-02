#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import sys
import operator


# Useful for very coarse version differentiation.
indexbytes = operator.getitem
intlist2bytes = bytes
# int2byte = operator.methodcaller('to_bytes', 1, 'big')
