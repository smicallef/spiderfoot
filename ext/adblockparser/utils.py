# -*- coding: utf-8 -*-
from __future__ import absolute_import

def split_data(data, pred):
    yes, no = [], []
    for d in data:
        if pred(d):
            yes.append(d)
        else:
            no.append(d)
    return [yes, no]
