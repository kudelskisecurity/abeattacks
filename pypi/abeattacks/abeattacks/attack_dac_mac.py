#!/usr/bin/env python

"""
This module contains methods to attack a dac mac implementation
based on https://eprint.iacr.org/2020/460.

It supposes that the user knows x_2 and a complete decryption attack 
can be mounted.

It recovers e(g, g)^{\ alpha_i \cdot s} and decrypts any ciphertext
in the system with independence of the policy.
"""

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.schemes.abenc.abenc_dacmacs_yj14 import DACMACS

def dac_mac_compute_pairing(user_k, ct_c2, x_1):
    a_1 = pair(user_k, ct_c2)

    return a_1 ** x_1

def dac_mac_get_egg(to_cancel, g_a, ct_c2, x_1, x_2, user_r, ct_c3):
    a_2 = pair(g_a, ct_c2)
    a_2 = a_2 ** (x_1 * x_2)

    # e(g^{ri*b}, g^{s/bi}})^x_1 

    a_3 = pair(user_r, ct_c3)
    a_3 = a_3 ** x_1

    cancel = a_2 * a_3

    return to_cancel / cancel



