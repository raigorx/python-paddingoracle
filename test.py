'''
Test decrypt and encrypt mode for
Padding Oracle Attack
~~~~~~~~~~~~~~~~~~~~~~~~~~
'''

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from paddingoracle import BadPaddingException, PaddingOracle


def test():
    '''
    Test decrypt and encrypt modes for padding oracle attack
    '''

    class PadBuster(PaddingOracle):
        '''
        Implementation of the abstract method oracle
        '''

        def oracle(self, data, **kwargs):
            _cipher = AES.new(key, AES.MODE_CBC, initial_vector)
            ptext = _cipher.decrypt(data)

            # unpad plaintext if Exception is raise the pad is invalid
            # otherwise is valid
            try:
                unpad(ptext, AES.block_size)
                return

            except Exception:
                raise BadPaddingException

        def analyze(self, **kwargs):
            return

    padbuster = PadBuster()

    for _ in range(100):
        key = os.urandom(AES.block_size)
        initial_vector = bytearray(os.urandom(AES.block_size))

        print("Testing padding oracle exploit in DECRYPT mode")
        cipher = AES.new(key, AES.MODE_CBC, initial_vector)

        teststring = b"The quick brown fox jumped over the lazy dog"

        data = pad(teststring, AES.block_size)
        ctext = cipher.encrypt(data)

        print("Key:        %r" % (key))
        print("IV:         %r" % (initial_vector))
        print("Plaintext:  %r" % (data))
        print("Ciphertext: %r" % (ctext))

        decrypted = padbuster.decrypt(
            ctext, block_size=AES.block_size, initial_vector=initial_vector)

        print("Decrypted:  %r" % (str(decrypted)))
        print("\nRecovered in %d attempts\n" % (padbuster.attempts))

        assert decrypted == data, \
            'Decrypted data %r does not match original %r' % (
                decrypted, data)

        print("Testing padding oracle exploit in ENCRYPT mode")

        teststring = "The quick brown fox jumped over the lazy dog"
        encrypted = padbuster.encrypt(teststring, block_size=AES.block_size)

        print("Key:        %r" % (key))
        print("IV:         %r" % (initial_vector))
        print("Plaintext:  %r" % (teststring))
        print("Ciphertext: %r" % (str(encrypted)))

        cipher2 = AES.new(key, AES.MODE_CBC, initial_vector)
        decrypted = unpad(cipher2.decrypt(encrypted)[
            AES.block_size:], AES.block_size)
        decrypted = decrypted.decode('utf-8')

        print("Decrypted:  %r" % (str(decrypted)))
        print("\nRecovered in %d attempts" % (padbuster.attempts))

        assert decrypted == teststring, \
            'Encrypted data %r does not decrypt to %r, got %r' % (
                encrypted, teststring, decrypted)


if __name__ == '__main__':
    test()
