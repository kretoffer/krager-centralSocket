import pytest

from centralSocket.appp.logic.Crypto import CryptoCipher

from random import randbytes

static_key_iv_array = [(randbytes(32), randbytes(16)) for i in range(0, 5)]


class TestCipher:
    range_params = (1, 10000, 1000)

    @classmethod
    def get_cipher(cls, static_key, iv) -> CryptoCipher:
        crypto_cipher = CryptoCipher(static_key, iv)
        crypto_cipher.client_public_key = crypto_cipher.public_RSA_key
        return crypto_cipher

    @pytest.mark.parametrize("static_key, iv", static_key_iv_array)
    def test_RSA_encode_decode(self, static_key, iv):
        crypto_cipher = self.get_cipher(static_key, iv)
        for i in range(*self.range_params):
            start_value = randbytes(i*8)
            encode = crypto_cipher.encodeRSA(start_value)
            decode = crypto_cipher.decodeRSA(encode)
            assert start_value == decode

    @pytest.mark.parametrize("static_key, iv", static_key_iv_array)
    def test_AES_encode_decode(self, static_key, iv):
        crypto_cipher = self.get_cipher(static_key, iv)
        for i in range(*self.range_params):
            start_value = randbytes(i*8)
            encode = crypto_cipher.encodeAES(start_value)
            decode = crypto_cipher.decodeAES(encode)
            assert start_value == decode

    @pytest.mark.parametrize("static_key, iv", static_key_iv_array)
    def test_full_encode_decode(self, static_key, iv):
        crypto_cipher = self.get_cipher(static_key, iv)
        for i in range(*self.range_params):
            start_value = randbytes(i*8)
            encode = crypto_cipher.encodeRSApAES(start_value)
            decode = crypto_cipher.decodeRSApAES(encode, False)
            assert start_value == decode

