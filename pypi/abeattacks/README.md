
# abeattacks

This python module contain the attacks against ABE schemes presented
at Black Hat Europe 2021 by Antonio de la Piedra and Marloes Venema.

At the CT-RSA 2021 conference, Venema and Alpár presented attacks against 11 ABE and MA-ABE schemes, including the highly cited DAC-MACS scheme with applications to the cloud. 

We demonstrate the practicality of the attacks providing:
	- A decryption attack against DAC-MACS, where a single user is able to decrypt ciphertexts with policies she cannot satisfy. This user does not even need to collude with other users or corrupt an authority. 
	- A decryption attack with corruption of one of the authorities against the YJ14-MA-ABE scheme. 
	- A decryption attack against the YCT14 scheme where two users collude in order to obtain a decryption key based on the work of Tan et al. and Herranz (2019). 

## Requirements

Install CHARM using the following commands:

```
add-apt-repository ppa:deadsnakes/ppa -y
apt update -y
apt install python3.7 python3.7-dev -y
apt install python3-virtualenv -y
apt install build-essential sudo python3-dev wget flex bison python3-pip libssl-dev libgmp10 libgmp-dev git openssl -y
rm -f /usr/bin/python && ln -s /usr/bin/python3.7 /usr/bin/python
rm -f /usr/bin/python3 && ln -s /usr/bin/python3.7 /usr/bin/python3
git clone https://github.com/JHUISI/charm
git checkout 55d82436d5da1a830fb16d6536700d9d61c0149d
./configure.sh
python3.7 -m pip install -r requirements.txt
cd charm/deps/pbc
make
ldconfig
cd charm/
make 
make install 
ldconfig
```

## References

	- https://www.blackhat.com/eu-21/briefings/schedule/index.html#practical-attacks-against-attribute-based-encryption-25058
	- https://eprint.iacr.org/2020/460 


