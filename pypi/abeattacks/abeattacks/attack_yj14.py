#!/usr/bin/env python

"""
Complete decryption attack against the YJ14 scheme.
It needs the corruption of one of the authorities
to obtain x_2.
"""

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.schemes.abenc.abenc_maabe_yj14 import MAABE

def yj14_corrupt_authority(k_1, c_1, k_2, c_2, mpk_1, x_2):
    p_1 = pair(k_1, c_1)
    p_2 = pair(k_2, c_2)
    p_3 = pair(mpk_1, c_1)
    p_3 = p_3 ** x_2

    return (p_1 / (p_2 * p_3))
 


