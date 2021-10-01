#!/usr/bin/env python

"""
# abeattacks

This python module contain the attacks against ABE schemes presented
at Black Hat Europe 2021 by Antonio de la Piedra and Marloes Venema.

At the CT-RSA 2021 conference, Venema and Alpár presented attacks against 11 ABE and MA-ABE schemes, including the highly cited DAC-MACS scheme with applications to the cloud. 

We demonstrate the practicality of the attacks providing:
	- A decryption attack against DAC-MACS, where a single user is able to decrypt ciphertexts with policies she cannot satisfy. This user does not even need to collude with other users or corrupt an authority. 
	- A decryption attack with corruption of one of the authorities against the YJ14-MA-ABE scheme. 
	- A decryption attack against the YCT14 scheme where two users collude in order to obtain a decryption key based on the work of Tan et al. and Herranz (2019). 

## References

	- https://www.blackhat.com/eu-21/briefings/schedule/index.html#practical-attacks-against-attribute-based-encryption-25058
	- https://eprint.iacr.org/2020/460 
"""

__version__ = "1.0.1"
__author__ = 'Antonio de la Piedra, Marloes Venema'


