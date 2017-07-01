# struct
# dwKeyLen = key size in bytes
# BLOBHEADER: 8 bytes
# typedef struct _PUBLICKEYSTRUC {
#     BYTE   bType; 1
#     BYTE   bVersion; 1
#     WORD   reserved; 2
#     ALG_ID aiKeyAlg; 4
# } BLOBHEADER, PUBLICKEYSTRUC;
# RSAPUBKEY: 12 bytes
# typedef struct _RSAPUBKEY {
#     DWORD   magic; 4
#     DWORD   bitlen; 4
#     DWORD   pubexp; 4
# } RSAPUBKEY;
# data: keyLen*2 + ((keyLen +1)/2)*5
#  N,p,q,dP,dQ,qP,d
#  N  = bytes little endian, padded to dwKeyLen with zero
#  p  = bytes little endian, padded to (dwKeyLen+1)/2
#  same for q dP qQ qP and d

import sys
import struct
import codecs
import gmpy2
from Crypto.Cipher import AES

if len(sys.argv) <= 2:
    print("Usage: %s rsa_key encrypted_key" % sys.argv[0], file=sys.stderr)
    sys.exit(1)

data = open(sys.argv[1], "rb").read()

def get_data(n):
    global data
    ret = data[:n]
    data = data[n:]
    return ret

def import_int(b):
    return int.from_bytes(b, "little", signed=False)

print("Parse RSA private key blob")
blob_header = struct.unpack("<BBHI", get_data(8))
pub_key = struct.unpack("<III", get_data(12))
keylen = pub_key[1]//8
subkeylen = (keylen+1)//2
N = import_int(get_data(keylen))
p = import_int(get_data(subkeylen))
q = import_int(get_data(subkeylen))
dP = import_int(get_data(subkeylen))
dQ = import_int(get_data(subkeylen))
iQ = import_int(get_data(subkeylen))
d = import_int(get_data(keylen))
print("N = %d" % N)
print("p = %d" % p)
print("q = %d" % q)
print("d = %d" % d)
print("N == p*q = %d" % int(N==p*q))
assert(N==p*q)

key = open(sys.argv[2],"rb").read()[12:]
print("Len encrypted key = %d" % len(key))
key = int.from_bytes(key, 'little', signed=False)
key = pow(key, d, N)
key = key.to_bytes(256, 'big', signed=False)
print("decrypted (with padding): ", codecs.encode(key,'hex'))

# Check padding (PKCS1 #2).
# It starts with 0x00 and 0x02. Then, there are non-null random bytes until a
# null byte is encountered. Actual data is after this null byte. Actual data
# must be 16 bytes.
assert(key[0] == 0)
assert(key[1] == 2)
assert(all(c != 0 for c in key[2:-17]))
assert(key[-17] == 0)
print("Padding is valid, AES key: %s" % codecs.encode(key[-16:], "hex"))
