import hashlib
import ecdsa
import os, sys, time
import threading
from binascii import hexlify
from base58 import b58encode

found = 'mepth'
threads = 50

def random_secret_exponent(curve_order):
    while True:
        bytes = os.urandom(32)
        random_hex = hexlify(bytes)
        random_int = int(random_hex, 16)
        if random_int >= 1 and random_int < curve_order:
            return random_int


def generate_private_key():
    curve = ecdsa.curves.SECP256k1
    se = random_secret_exponent(curve.order)
    from_secret_exponent = ecdsa.keys.SigningKey.from_secret_exponent
    return from_secret_exponent(se, curve, hashlib.sha256).to_string()


def get_public_key_uncompressed(private_key_bytes):
    k = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    return b'\04' + k.get_verifying_key().to_string()  # 0x04 = uncompressed key prefix


def get_bitcoin_address(public_key_bytes, prefix=b'\x00'):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(public_key_bytes).digest())
    r = prefix + ripemd160.digest()
    checksum = hashlib.sha256(hashlib.sha256(r).digest()).digest()[0:4]
    return b58encode(r + checksum)

count, count_t = 0, 0

def thread():
    global count
    while True:
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).to_string()
        public_key = get_public_key_uncompressed(private_key)
        address = get_bitcoin_address(public_key).decode('utf-8')
        count += 1
        if str(address).lower().startswith('1' + found):
            print('FOUND! ' + address)
            path = 'wallets/' + address
            os.mkdir(path)
            f = open(path + '/wallet.txt', "w")
            f.write('private key: %s\npublic key uncompressed: %s\nbtc address: %s' % (hexlify(private_key).decode('utf-8'), hexlify(public_key).decode('utf-8'), address))
            f.close()

def main():
    global count_t
    for i in range(threads):
        th = threading.Thread(target=thread, args=())
        th.daemon = False
        count_t += 1
        th.start()
        sys.stdout.write('\r[{0}/{1}]'.format(count_t, threads))
    while True:
        sys.stdout.write('\r[{0}/{1}]'.format(int(time.time() * 1000), count))

if __name__ == '__main__':
    main()
