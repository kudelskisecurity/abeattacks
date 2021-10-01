
# Attack on yao et al. 2014 (YCT14)
# presented on "Enhancement of a lightweight
# attribute-based encryption scheme for the internet
# of things".

from charm.schemes.abenc.abenc_yct14 import EKPabe                         
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.ABEnc import ABEnc
from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.core.math.pairing import hashPair as extractor


# example of standard use

group = PairingGroup('MNT224')
kpabe = EKPabe(group)
attributes = [ 'ONE', 'TWO', 'THREE', 'FOUR' ]

# setup

(master_public_key, master_key) = kpabe.setup(attributes)
policy = '(ONE or THREE) and (THREE or TWO)'

# keygen

secret_key = kpabe.keygen(master_public_key, master_key, policy)

# encrypt

msg = b"Some Random Message"
cipher_text = kpabe.encrypt(master_public_key, msg, attributes)

# decrypt

decrypted_msg = kpabe.decrypt(cipher_text, secret_key)

print("Standard use: ", decrypted_msg == msg)

# Presentation of the attack
# the target is to decrypt a message encrypted with
# attribute x = ONE.
# Two parties with attr y = TWO and z = THREE
# collaborate

group = PairingGroup('MNT224')
kpabe = EKPabe(group)
attributes = [ 'ONE', 'TWO', 'THREE', 'FOUR' ]

(master_public_key, master_key) = kpabe.setup(attributes)

policy_y = '(TWO)'
policy_z = '(THREE)'

# generation of keys 

sk_y = kpabe.keygen(master_public_key, master_key, policy_y)
sk_z = kpabe.keygen(master_public_key, master_key, policy_z)

# generation of target cphertext and decryption key for user x

policy_x = '(ONE)'
sk_x = kpabe.keygen(master_public_key, master_key, policy_x)
attr_target_ct = ['ONE']
msg = b"recover me :)"
target_ct = kpabe.encrypt(master_public_key, msg, attr_target_ct)
decrypted_msg = kpabe.decrypt(target_ct, sk_x)
assert (decrypted_msg == msg) 
print("Correction ok")

# attack parameters (public)

PK = master_public_key
p_x = kpabe.attribute['ONE']
p_y = kpabe.attribute['TWO']
p_z = kpabe.attribute['THREE']

# Phase 1
# x = one, y = two, z = three

# a1 = y or z
# a2 = x and y
# a3 = z or ( x and y)

# attack: 2 users with attrs TWO, THREE collude to obtain the private key
# of attr X, ONE

a_1 = '(TWO or THREE)'
a_2 = '(ONE or TWO)'
a_3 = 'THREE or (ONE and TWO)'

d_a_1 = kpabe.keygen(master_public_key, master_key, a_1)
d_a_2 = kpabe.keygen(master_public_key, master_key, a_2)
d_a_3 = kpabe.keygen(master_public_key, master_key, a_3)

# invalid if we don't have access to the attribute
# only to verify the attack
test_x = kpabe.keygen(master_public_key, master_key, 'ONE')['Du']['ONE']
print("key x: ", test_x)

# Phase 2

d_y = d_a_1['Du']['TWO']
d_z = d_a_1['Du']['THREE']
d_u_x = d_a_2['Du']['ONE']
d_u_y = d_a_2['Du']['TWO']
d_u_x_prima = d_a_3['Du']['ONE']
d_u_y_prima = d_a_3['Du']['TWO']

"""
util = SecretUtil(group, True)

policy = util.createPolicy(a_2)
policy = util.createPolicy(a_3)

attrs = util.prune(policy, ['THREE'])
print(attrs[0].getAttributeAndIndex())
"""

# attack

x = d_u_x - d_u_x_prima
y = (d_u_y - d_u_y_prima)/2

d_plus = x * (1/y) * d_y

print("x: ", x)
print("y: ", y)
print("d plus: ", d_plus)

assert (d_plus == test_x) 
print("ATTACK SUCCESFUL, CAN RECOVER X PRIVATE KEY")

new_x = {'policy': '(ONE)', 'Du': {'ONE': d_plus}}
try_decrypt = kpabe.decrypt(target_ct, new_x);
assert(try_decrypt == msg)
print("DECRYPTION ATTACK SUCCESSFUL")

"""
policy_x = '(ONE)'
sk_x = kpabe.keygen(master_public_key, master_key, policy_x)
attr_target_ct = ['ONE']
msg = b"recover me :)"  
target_ct = kpabe.encrypt(master_public_key, msg, attr_target_ct)
decrypted_msg = kpabe.decrypt(target_ct, sk_x)
assert (decrypted_msg == msg) 
print("Correction ok")
"""

