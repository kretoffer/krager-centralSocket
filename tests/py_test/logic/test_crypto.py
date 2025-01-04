import pytest

from centralSocket.appp.logic.Crypto import CryptoCipher

from random import randbytes
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
import json
import time

static_key_iv_array = [(randbytes(32), randbytes(16)) for i in range(0, 5)]


class TestCipher:
    range_params = (1, 50000, 2000)

    @classmethod
    def get_cipher(cls, static_key, iv, parameters=None, RSA_key=None, rsa_sinc: bool = True) -> CryptoCipher:
        crypto_cipher = CryptoCipher(static_key, iv, parameters=parameters, public_RSA_key=RSA_key)
        if rsa_sinc:
            crypto_cipher.client_public_RSA_key = crypto_cipher.public_RSA_key
        return crypto_cipher

    @pytest.mark.parametrize("static_key, iv", static_key_iv_array)
    def test_RSA_encode_decode(self, static_key, iv):
        crypto_cipher = self.get_cipher(static_key, iv, parameters=False)
        for i in range(*self.range_params):
            start_value = randbytes(i*8)
            encode = crypto_cipher.encodeRSA(start_value)
            decode = crypto_cipher.decodeRSA(encode)
            assert start_value == decode

    @pytest.mark.parametrize("static_key, iv", static_key_iv_array)
    def test_AES_encode_decode(self, static_key, iv):
        crypto_cipher = self.get_cipher(static_key, iv, parameters=False)
        for i in range(*self.range_params):
            start_value = randbytes(i*8)
            encode = crypto_cipher.encodeAES(start_value)
            decode = crypto_cipher.decodeAES(encode)
            assert start_value == decode

    @pytest.mark.parametrize("static_key, iv", static_key_iv_array)
    def test_RSApAES_encode_decode(self, static_key, iv):
        crypto_cipher = self.get_cipher(static_key, iv, parameters=False)
        for i in range(*self.range_params):
            start_value = randbytes(i*8)
            encode = crypto_cipher.encodeRSApAES(start_value)
            decode = crypto_cipher.decodeRSApAES(encode, False)
            assert start_value == decode

    @pytest.mark.parametrize("static_key, iv", static_key_iv_array)
    def test_DH_system(self, static_key, iv):
        crypto_cipher_A = self.get_cipher(static_key, iv)
        crypto_cipher_B = self.get_cipher(static_key, iv, parameters=crypto_cipher_A.parameters)
        crypto_cipher_A.DH_public_key = crypto_cipher_B.my_DH_public_key
        crypto_cipher_B.DH_public_key = crypto_cipher_A.my_DH_public_key
        assert crypto_cipher_A._key == crypto_cipher_B._key

    @pytest.mark.parametrize("static_key, iv", static_key_iv_array)
    def test_cyrcular_full(self, static_key, iv):
        t_start_connect = time.time()
        crypto_cipher_A = self.get_cipher(static_key, iv, parameters=False, rsa_sinc=False)
        crypto_cipher_B = self.get_cipher(static_key, iv, RSA_key=crypto_cipher_A.public_RSA_key, rsa_sinc=False)
        m_1 = crypto_cipher_B.encodeRSA(crypto_cipher_B.public_RSA_key.export_key())
        crypto_cipher_A.client_public_RSA_key = RSA.import_key(crypto_cipher_A.decodeRSA(m_1))
        data = {"userID": "djfjdfjd"}
        m_2 = crypto_cipher_A.encodeRSA(json.dumps(data))
        assert json.loads(crypto_cipher_B.decodeRSA(m_2).decode('utf-8')) == data
        m_3_1 = crypto_cipher_B.encodeRSApAES(crypto_cipher_B.parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        ))
        m_3_2 = crypto_cipher_B.encodeRSApAES(crypto_cipher_B.my_DH_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        crypto_cipher_A.parameters = crypto_cipher_A.decodeRSApAES(m_3_1)
        m_4 = crypto_cipher_A.encodeRSApAES(crypto_cipher_A.my_DH_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        crypto_cipher_B.DH_public_key = crypto_cipher_B.decodeRSApAES(m_4)
        crypto_cipher_A.DH_public_key = crypto_cipher_A.decodeRSApAES(m_3_2)
        assert crypto_cipher_A._key == crypto_cipher_B._key
        t_end_connect = time.time()
        print(f"\n\nconnect time: {t_end_connect-t_start_connect}\n" + "-"*50 + "\n")
        for i in range(*self.range_params):
            message = randbytes(i)
            e_message = crypto_cipher_A.encode(message)
            d_message = crypto_cipher_B.decode(e_message)
            assert message == d_message

