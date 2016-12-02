# Created by Davanum Srinivas

import ecdsa
import ecdsa.der
import ecdsa.util
import hashlib
import os
import re
import struct
import sys
import time
import qrcode
from PIL import Image

repeat = int(sys.argv[1])

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58encode(n):
    result = ''
    while n > 0:
        result = b58[n%58] + result
        n /= 58
    return result

def base256decode(s):
    result = 0
    for c in s:
        result = result * 256 + ord(c)
    return result

def countLeadingChars(s, ch):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count

# https://en.bitcoin.it/wiki/Base58Check_encoding
def base58CheckEncode(version, payload):
    s = chr(version) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    leadingZeros = countLeadingChars(result, '\0')
    return '1' * leadingZeros + base58encode(base256decode(result))

def privateKeyToWif(key_hex):
    return base58CheckEncode(0x80, key_hex.decode('hex'))

def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')

def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
    return base58CheckEncode(0, ripemd160.digest())

def keyToAddr(s):
    return pubKeyToAddr(privateKeyToPublicKey(s))


count = 1
fecha = time.strftime("%d_%m_%Y_%H_%M_%S")
os.mkdir(fecha)
while (count <= repeat):
    subfolder = fecha + "/" + str(count)
    os.mkdir(subfolder)
    # Generate a random private key
    private_key = os.urandom(32).encode('hex')

    # Write the Secret Exponent/HEX, Private Key and Address to a text file.
    output = subfolder + "/" + str(count)+'.txt'
    privatekeyout = privateKeyToWif(private_key)
    publickeyout = keyToAddr(private_key)
    file = open(output, "w")
    # Write the Secret Exponent/HEX, Private Key and Address to a text file.
    file.write("Secret Exponent/HEX (Uncompressed) : %s \n" % private_key)

    file.write("Private Key     : %s \n" % privatekeyout)

    file.write("Address         : %s \n" % publickeyout)

    file.close()

    qrpublic = subfolder + "/" + str(count)+'_public.png'
    qrprivate = subfolder + "/" + str(count)+'_private.png'
    imgpublic = qrcode.make(publickeyout)
    imgprivate = qrcode.make(privatekeyout)
    fpublic = open(qrpublic, "wb")
    fprivate = open(qrprivate, "wb")
    imgpublic.save(fpublic)
    imgprivate.save(fprivate)
    fpublic.close()
    fprivate.close()

    print str(count)+'.txt' + ' generada.'
    count = count + 1


