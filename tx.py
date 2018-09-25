# Python 2.7.6 - Super simple Elliptic Curve Presentation. No imported libraries, wrappers, nothing. # For educational purposes only
import hashlib
import base58
import binascii
# Below are the public specs for Bitcoin's curve - the secp256k1
Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 # The proven prime
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field
Acurve = 0; Bcurve = 7 # This defines the curve. y^2 = x^3 + Acurve * x + Bcurve
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
GPoint = (Gx,Gy) # This is our generator point. Tillions of dif ones possible

#Individual Transaction/Personal Information
privKey = 2
#int("0x9df5a907ff17ed6a4e02c00c2c119049a045f52a4e817b06b2ec54eb68f70079", 0)
RandNum = 28695618543805844332113829720373285210420739438570883203839696518176414791234 #replace with a truly random number
HashOfThingToSign = 86032112319101611046176971828093669637772856272773459297323797145286374828050
# the hash of your message/transaction

def modinv(a,n=Pcurve): #Extended Euclidean Algorithm/'division' in elliptic curves
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1:
        ratio = high/low
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ECadd(xp,yp,xq,yq): # Not true addition, invented for EC. It adds Point-P with Point-Q.
    m = ((yq-yp) * modinv(xq-xp,Pcurve)) % Pcurve
    xr = (m*m-xp-xq) % Pcurve
    yr = (m*(xp-xr)-yp) % Pcurve
    return (xr,yr)

def ECdouble(xp,yp): # EC point doubling,  invented for EC. It doubles Point-P.
    LamNumer = 3*xp*xp+Acurve
    LamDenom = 2*yp
    Lam = (LamNumer * modinv(LamDenom,Pcurve)) % Pcurve
    xr = (Lam*Lam-2*xp) % Pcurve
    yr = (Lam*(xp-xr)-yp) % Pcurve
    return (xr,yr)

def EccMultiply(xs,ys,Scalar): # Double & add. EC Multiplication, Not true multiplication
    if Scalar == 0 or Scalar >= N: raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(Scalar))[2:]
    Qx,Qy=xs,ys
    for i in range (1, len(ScalarBin)): # This is invented EC multiplication.
        Qx,Qy=ECdouble(Qx,Qy);
        #print "DUB", Qx; print
        if ScalarBin[i] == "1":
            Qx,Qy=ECadd(Qx,Qy,xs,ys);
            #print "ADD", Qx; print
    return (Qx,Qy)

print; print "******* Public Key Generation *********"
xPublicKey, yPublicKey = EccMultiply(Gx,Gy,privKey)
#https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
print("step 0: private key ---")
print "the private key (in base 10 format):"; print privKey
print "the private key (in base 16 format):"; print hex(privKey); print

print("step 1: generate pubkey ---")
print "the uncompressed public key (starts with '04' & is not the public address):"
#[2:-1]: converts to hex, takes out leading 0x, and trailing L
un_pub_key = str("04") + str(hex(xPublicKey)[2:-1]) + str(hex(yPublicKey)[2:-1])
print(un_pub_key); print

if(int(yPublicKey) % 2 == 0): first_byte = "02"
else: first_byte = "03"
in_data = (first_byte + hex(xPublicKey)[2:-1])
print("02 if y is even, 03 if y is odd + x coordinate of uncompressed pubkey:")
print(in_data); print

print("step 2: hash of 1 byte plus x coordinate ---")
sha1 = hashlib.sha256()
#must decode to hex before hashing
sha1.update(in_data.decode('hex'))
hash1 = sha1.digest()
print(hash1.encode('hex')); print

print("step 3: perform ripemd160 on previous result(hash1) ---")
ripemd = hashlib.new('ripemd160')
ripemd.update(hash1)
print(ripemd.hexdigest()); print

print("step 4: Add byte in front of RIPEMD-160 hash (0x00 for Main Network) ---")
ripemd_ext = "00" + ripemd.hexdigest()
print(ripemd_ext); print

print("step 5: sha256 previous hash ---")
ripemd_ext = ripemd_ext.decode('hex')
sha2 = hashlib.sha256()
sha2.update(ripemd_ext)
hash2 = sha2.digest()
print(hash2.encode('hex')); print

print("step 6: sha256 previous hash ---")
sha3 = hashlib.sha256()
sha3.update(hash2)
hash3 = sha3.digest()
print(hash3.encode('hex')); print

print("step 7: first 4 bytes of previous hash. This is the address checksum ---")
print(hash3.encode('hex')[:8]); print

print("step 8: add 4 bytes from step 7 to end of step 4 hash ---")
hash4 = ripemd_ext.encode('hex') + hash3.encode('hex')[:8]
print(hash4); print

print("step 9: base58 encode, bitcoin address compressed ---")
bit_address = base58.b58encode(hash4.decode('hex'))
print(bit_address)


print; print "******* Signature Generation *********"
xRandSignPoint, yRandSignPoint = EccMultiply(Gx,Gy,RandNum)
r = xRandSignPoint % N; print "r =", r
s = ((HashOfThingToSign + r*privKey)*(modinv(RandNum,N))) % N; print "s =", s

print; print "******* Signature Verification *********>>"
w = modinv(s,N)
xu1, yu1 = EccMultiply(Gx,Gy,(HashOfThingToSign * w)%N)
xu2, yu2 = EccMultiply(xPublicKey,yPublicKey,(r*w)%N)
x,y = ECadd(xu1,yu1,xu2,yu2)
print r==x; print

#txid is double sha of whole tx
double_sha = hashlib.sha256()
raw_tx_input = "0100000001be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396000000001976a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88acffffffff0123ce0100000000001976a914a2fd2e039a86dbcf0e1a664729e09e8007f8951088ac0000000001000000"
double_sha.update(raw_tx_input.decode('hex'))
double_sha2 = hashlib.sha256()
double_sha2.update(double_sha.digest())
print (double_sha2.digest())[::-1].encode('hex')
#[::-1] reverses the bytes

#plan: create own wallet, import privkey, calculate own pubkey, send coin to pubaddress, send it to myself


print "create tx"
version_num = "01 00 00 00"
input_count = "01"
previous_output_hash = (double_sha2.digest())[::-1].encode('hex')
#previous output hash is reversed
previous_output_index = "00 00 00 00"
#previous output index starts at 0, and is 4 bytes
input_script_len = "8a"
scriptSig = "47 30 44"
sequence = "ff ff ff ff"
output_count = "01"
value = 1 #8 bytes, reversed, little endian
output_script_len = "19"
scriptPubKey = "76 a9 14 c8 e9 09 96 c7 c6 08 0e e0 62 84 60 0c 68 4e d9 04 d1 4c 5c 88 ac"
block_lock_time = "00 00 00 00"

#privkey to address VfnUMhLC215xQ2vVuAE3HBbiwC3asoAhcc: Kwe2SRtVLGa4QgjKRDBKkhVp6rwFgWFJALoA9mz8iBQdFJyvMjZn
print ("wallet import format to privkey")
wif_key = "Kwe2SRtVLGa4QgjKRDBKkhVp6rwFgWFJALoA9mz8iBQdFJyvMjZn"
#base58decode
wif_key_base58de = base58.b58decode(wif_key)
imported_priv_key = wif_key_base58de.encode('hex')
print("unpruned priv key: ")
print (imported_priv_key)
#drop the last 4 bytes, and leading 80
imported_priv_key = imported_priv_key[2:-8]
#if WIF starts with K or L the last byte will be 01. remove it
if(wif_key[0] == "K" or wif_key[0] == "L"):
    imported_priv_key = imported_priv_key[:-2]
print(imported_priv_key)
