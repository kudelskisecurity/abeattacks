
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.schemes.abenc.abenc_dacmacs_yj14 import DACMACS

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

    # XXX: they do not encrypt the certificate
    # YAY! we have access to x_1 = z_j and x_2 = u_j
    
    # MVE: we have the following mappings from code to attack in paper:
    #       x_1 = z_j, x_2 = u_j
    #       r_i = t
    #       b = a, b_i = beta
    #       s = s

    x_1 = alice['keys'][1]
    x_2 = users[alice['id']]['u']
 
    #print("x1: ", x_1)
    #print("x2: ", x_2)

    # attack 1: alice decrypts a ciphertext for her, but she does not 
    # satisfy the policy e.g. ONE vs (TWO and THREE)   
 
    #for attr in authorityAttributes[0:-1]:
    # we give alice only ONE
    USK_t_alice = dac.keygen(GPP, authorities[authority1], "ONE", users[alice['id']], alice['authoritySecretKeys1'])
    #print("pairing_1: ", USK_t['K'])
    p_1 = USK_t_alice['K']
    # MVE: maybe you can give Alice a secret key for only one attribute, e.g. ONE, so she doesn't satisfy the policies? 
    
    k1 = groupObj.random(GT)
    
    policy_str = '(TWO and THREE)'
    
    CT1 = dac.encrypt(GPP, policy_str, k1, authorities[authority1])

    p_2 = CT1['C2'] 
    # MVE: p_2 = g^s

    # attack

    a_1 = pair(p_1, p_2)
    a_1 = a_1 ** x_1
    
    # MVE: note: a_1 = e(g,g)^{x_1 s( \alpha / x_1 + x_2 * b + b * r_i / b_i)}
    # to cancel: e(g,g)^{x_1 * x_2 * s * b} and e(g,g)^{x_1 r_i s b / b_i}

    # to cancel
    # e(g^b, g^s)^(x1 * x2)
    
    a_2 = pair(GPP['g_a'], p_2)
    a_2 = a_2 ** (x_1 * x_2)
 
    # e(g^{ri*b}, g^{s/bi}})^x_1 

    tmp_1 = USK_t_alice['R']
    tmp_2 = CT1['C3']
    a_3 = pair(tmp_1, tmp_2)
    a_3 = a_3 ** x_1

    cancel = a_2 * a_3
    verify_2 = a_1/ cancel 

    # validation of the attack

    verify_1 = CT1['C1'] / k1

    assert verify_1 == verify_2, 'FAILED ATTACK'
    print('SUCCESSFUL ATTACK #1 (alice vs alice, unsatisfiable policy)')

    #print("same? ", verify_1)
    #print("same? ", verify_2)

    # decryption attack

    k_recover = CT1['C1']/verify_2
    assert k1 == k_recover, 'FAILED DECRYPTION ATTACK'
    print('DECRYPTION ATTACK SUCCESFUL')

    """
    print("Norma decryption is possible ?")

    # normal decryption
    
    TK1 = dac.generateTK(GPP, CT1, alice['authoritySecretKeys1'], alice['keys'][0])
    PT1 = dac.decrypt(CT1, TK1, alice['keys'][1])
    
    print("k:", k1)
    print("PT:", PT1)
    
    assert k1 == PT1, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')

    """

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

    a_1 = pair(p_1, p_2)
    a_1 = a_1 ** x_1

    # to cancel
    # e(g^b, g^s)^(x1 * x2)
    
    a_2 = pair(GPP['g_a'], p_2)
    a_2 = a_2 ** (x_1 * x_2)
 
    # e(g^{ri*b}, g^{s/bi}})^x_1 

    tmp_1 = USK_t_alice['R'] #USK_t_bob['R']
    tmp_2 = ct_bob['C3']
    a_3 = pair(tmp_1, tmp_2)
    a_3 = a_3 ** x_1

    cancel = a_2 * a_3
    verify_bob = a_1/ cancel 

    k_bob_recover = ct_bob['C1']/verify_bob
    assert k_bob == k_bob_recover, 'FAILED ATTACK AGAINST BOB'
    print('ATTACK AGAINST BOB SUCCESFUL (attack #2: alice decrypts bobs ciphertext, also the policy does not satisfy for alice)')



