#!/usr/bin/env python

"""
Attack on yao et al. 2014 (YCT14)
presented on "Enhancement of a lightweight
attribute-based encryption scheme for the internet
of things".
"""

from charm.schemes.abenc.abenc_yct14 import EKPabe                         
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.ABEnc import ABEnc
from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.core.math.pairing import hashPair as extractor

"""
Two users with different attributers collude to obtain the private key
of another (d_x).
"""

def yct14_collude_function(d_y, d_z, d_u_x, d_u_y, d_u_x_prima, d_u_y_prima):
    x = d_u_x - d_u_x_prima
    y = (d_u_y - d_u_y_prima)/2
    d_plus = x * (1/y) * d_y

    return d_plus

