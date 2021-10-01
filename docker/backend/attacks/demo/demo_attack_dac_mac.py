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

from abeattacks import attack_dac_mac

if __name__ == "__main__":

    print("dac macs playground")

    print("alice has acces to the system, she performs the attack and recovers C1/k for a specific authority")

    groupObj = PairingGroup('SS512')
    dac = DACMACS(groupObj)
    GPP, GMK = dac.setup()

    users = {} # public user data
    authorities = {}

    authorityAttributes = ["ONE", "TWO", "THREE", "FOUR"]
    authority1 = "authority1"

    dac.setupAuthority(GPP, authority1, authorityAttributes, authorities)

    alice = { 'id': 'alice', 'authoritySecretKeys1': {},  'authoritySecretKeys2': {}, 'keys': None }
    alice['keys'], users[alice['id']] = dac.registerUser(GPP)

    x_1 = alice['keys'][1]
    x_2 = users[alice['id']]['u']

    # attack 1: alice decrypts a ciphertext for her, but she does not 
    # satisfy the policy e.g. ONE vs (TWO and THREE)   

    USK_t_alice = dac.keygen(GPP, authorities[authority1], "ONE", users[alice['id']], alice['authoritySecretKeys1'])
    p_1 = USK_t_alice['K']
    k1 = groupObj.random(GT)
    policy_str = '(TWO and THREE)'
    CT1 = dac.encrypt(GPP, policy_str, k1, authorities[authority1])

    p_2 = CT1['C2'] 

    # attack

    pair_ = attack_dac_mac.dac_mac_compute_pairing(p_1, p_2, x_1)
    egg = attack_dac_mac.dac_mac_get_egg(pair_, GPP['g_a'], CT1['C2'], x_1, x_2, USK_t_alice['R'], CT1['C3'])

    # validation of the attack

    verify_1 = CT1['C1'] / k1
    assert verify_1 == egg, 'FAILED ATTACK'
    print('SUCCESSFUL ATTACK #1 (alice vs alice, unsatisfiable policy)')

    # decryption attack

    k_recover = CT1['C1']/egg
    assert k1 == k_recover, 'FAILED DECRYPTION ATTACK'
    print('DECRYPTION ATTACK SUCCESFUL')

    # decryption other data owners keys: alice vs bob
    # alice decrypts bob's ciphertext. bob's policy is not
    # satisfy anyway by alice

    print("bob is a data owner with ciphertexts in the system")

    bob = { 'id': 'bob', 'authoritySecretKeys1': {},  'authoritySecretKeys2': {}, 'keys': None }
    bob['keys'], users[bob['id']] = dac.registerUser(GPP)

    #for attr in authorityAttributes[0:-1]:
    USK_t_bob = dac.keygen(GPP, authorities[authority1], "FOUR", users[bob['id']], bob['authoritySecretKeys1'])

    k_bob = groupObj.random(GT)

    policy_bob = '(THREE and TWO)'

    ct_bob = dac.encrypt(GPP, policy_bob, k_bob, authorities[authority1])

    # alice decrypts bob ciphertext even if she does not have THREE, FOUR attributes
    p_1 = USK_t_alice['K'] # USK_t_bob['K']
    x_1 = alice['keys'][1] #bob['keys'][1]
    x_2 = users[alice['id']]['u'] # users[bob['id']]['u']

    p_2 = ct_bob['C2'] 

    # attack

    pair_ = attack_dac_mac.dac_mac_compute_pairing(p_1, p_2, x_1)
    egg = attack_dac_mac.dac_mac_get_egg(pair_, GPP['g_a'], ct_bob['C2'], x_1, x_2, USK_t_alice['R'], ct_bob['C3'])
    k_bob_recover = ct_bob['C1']/egg

    assert k_bob == k_bob_recover, 'FAILED ATTACK AGAINST BOB'
    print('ATTACK AGAINST BOB SUCCESFUL (attack #2: alice decrypts bobs ciphertext, also the policy does not satisfy for alice)')



