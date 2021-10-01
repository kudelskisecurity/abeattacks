
"""
Complete decryption attack against the YJ14 scheme.
It needs the corruption of one of the authorities
to obtain x_2.
"""

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.schemes.abenc.abenc_maabe_yj14 import MAABE

import attack_yj14

if __name__ == "__main__":

    print("maabe yj14")

    groupObj = PairingGroup('SS512')
    maabe = MAABE(groupObj)

    # 1. setup
    GPP, GMK = maabe.setup()
   
    # 2. authority configuration 
    users = {} # public user data
    authorities = {}
    authorityAttributes = ["ONE", "TWO", "THREE", "FOUR"]
    authority1 = "authority1"
    maabe.setupAuthority(GPP, authority1, authorityAttributes, authorities)
   
    # 3. user configuration / alice, with attr ONE of the authority 
    alice = { 'id': 'alice', 'authoritySecretKeys': {}, 'keys': None }
    alice['keys'], users[alice['id']] = maabe.registerUser(GPP)
    SK_i = maabe.keygen(GPP, authorities[authority1], "ONE", users[alice['id']], alice['authoritySecretKeys'])
 
    # 3. user configuration / bob with attr FOUR of the authority 
    bob = { 'id': 'bob', 'authoritySecretKeys': {}, 'keys': None }
    bob['keys'], users[bob['id']] = maabe.registerUser(GPP)
    SK_bob_i = maabe.keygen(GPP, authorities[authority1], "FOUR", users[bob['id']], alice['authoritySecretKeys'])
  
    pk_1 = alice['keys'][0]
    sk_2 = alice['keys'][1] 
    pk_2 = users[alice['id']]['pk']    
    sk_1 = users[alice['id']]['sk']

    ## attack 1: I try to decrypt a CT with a policy
    ## I cannot fulfill. Then I recover e(g,g)^{alpha_i \cdot s}
    ## to facilitate things :)
 
    # 4. encryption 
    k = groupObj.random(GT)
    policy_str = '(THREE and FOUR)'
    CT = maabe.encrypt(GPP, policy_str, k, authorities[authority1])
 
    # 4.5. bob encryption 
    k_bob = groupObj.random(GT)
    policy_str_bob = '(TWO or FOUR)'
    CT_bob = maabe.encrypt(GPP, policy_str_bob, k_bob, authorities[authority1])
   
    # 5. decryption (alice) 
    PT = maabe.decrypt(GPP, CT, alice)

    if k == PT:
        print("Decryption succesfull")
    else:
        print("I cannot decrypt CT using normal means")
    
    #print("k:", k)
    #print("PT", PT)
    #assert k == PT, 'FAILED DECRYPTION!'
    #print('SUCCESSFUL DECRYPTION')

    # attack, recovering e(g, g)^{\alpha_i \cdot s}

    egg = attack_yj14.yj14_corrupt_authority(SK_i['K'], CT['C2'], SK_i['KS'], CT['C3'], GPP['g_a'], sk_1)
 
    verify_1 =  egg # p_1 / (p_2 * p_3)
    verify_2 = CT['C1'] / k
    assert verify_1 == verify_2, 'I cannot recover e(g,g)^{alpha * s}'
    print('e(g,g)^{alpha * s} recovered :)') 

    # attack 2: recovering bob's CTs

    egg = attack_yj14.yj14_corrupt_authority(SK_i['K'], CT_bob['C2'], SK_i['KS'], CT_bob['C3'], GPP['g_a'], sk_1)
    verify_1 = egg # p_1 / (p_2 * p_3)
    
    # obtaining bob k

    k_bob_recovered = CT_bob['C1'] / verify_1
    assert k_bob_recovered == k_bob, 'I cannot recover bobs k'
    print('I can recover bobs k')



