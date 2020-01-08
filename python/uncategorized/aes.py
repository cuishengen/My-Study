#!/usr/bin/env python

import binascii
import struct

import base64
from Crypto.Cipher import AES


class USE_AES:
    """
    AES
    除了MODE_SIV模式key长度为：32, 48, or 64,
    其余key长度为16, 24 or 32
    详细见AES内部文档
    CBC模式传入iv参数
    本例使用常用的ECB模式
    """

    def __init__(self, key):
        if len(key) > 32:
            key = key[:32]
        self.key = self.to_16(key)

    def to_16(self, key):
        """
        转为16倍数的bytes数据
        :param key:
        :return:
        """
        key = bytearray.fromhex(key)
        while len(key) % 16 != 0:
            key += b'\0'
            print("to_16")
        #key = key[::-1]     #反转
        #print(str(binascii.b2a_hex(key)))
        return key  # 返回bytes

    def aes(self):
        return AES.new(self.key, AES.MODE_ECB) # 初始化加密器

    def encrypt(self, text):
        aes = self.aes()
        return str(base64.encodebytes(aes.encrypt(self.to_16(text))),
                   encoding='utf8').replace('\n', '')  # 加密
                   
    def encrypt_ext(self, text):
        aes = self.aes()
        return str(binascii.b2a_hex(aes.encrypt(bytes().fromhex((text)))))  # 加密
        
    def encrypt_ext1(self, text):
        aes = self.aes()
        return str(binascii.b2a_hex(aes.encrypt(text.encode('hex'))))  # 加密
        

    def decodebytes(self, text):
        aes = self.aes()
        return str(aes.decrypt(base64.decodebytes(bytes(
            text, encoding='utf-8'))).rstrip(b'\0').decode("utf-8"))  # 解密


filename = r'C:\msys64\home\Administrator\Cui\py\airpods pro bats.cfa'

def check_result(str):
    str = str[2:]

    #BD_ADDR: 0x5b-ea-3b-e4-f3-62:
    if str[0:2] == '62' or str[30:32] == '62':
        if str[2:4] == 'f3' or str[28:30] == 'f3':
            if str[4:6] == 'e4' or str[26:28] == 'e4':
                print("success:" + str)

    if str[0:2] == 'e4' or str[30:32] == 'e4':
        if str[2:4] == 'f3' or str[28:30] == 'f3':
            if str[4:6] == '62' or str[26:28] == '62':
                print("success:" + str)
                
    #BD_ADDR: 0x79-72-23-31-bd-a8          
    if str[0:2] == 'a8' or str[30:32] == 'a8':
        if str[2:4] == 'bd' or str[28:30] == 'bd':
            if str[4:6] == '31' or str[26:28] == '31':
                print("success:" + str)

    if str[0:2] == '31' or str[30:32] == '31':
        if str[2:4] == 'bd' or str[28:30] == 'bd':
            if str[4:6] == 'a8' or str[26:28] == 'a8':
                print("success:" + str)
                
    #BD_ADDR: 0x7a-01-24-74-90-8c        
    if str[0:2] == '8c' or str[30:32] == '8c':
        if str[2:4] == '90' or str[28:30] == '90':
            if str[4:6] == '74' or str[26:28] == '74':
                print("success:" + str)

    if str[0:2] == '74' or str[30:32] == '74':
        if str[2:4] == '90' or str[28:30] == '90':
            if str[4:6] == '8c' or str[26:28] == '8c':
                print("success:" + str)

addr1 = "62f3e43bea5b"
addr2 = "8c907424017a"
    
#r'C:\Windows\system.ini'
if __name__ == '__main__':
    #aes_test = USE_AES('\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'))
    key = "000102030405060708090a0b0c0d0e0f"
    aes_test = USE_AES(key)
    #encrypt = aes_test.encrypt_ext(str(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'))
    encrypt = aes_test.encrypt_ext('00112233445566778899aabbccddeeff')
    #print(encrypt)
    #69c4e0d86a7b0430d8cdb78070b4c55a
    check_result(encrypt)
    
    ''' # Core 4.2 page 2380 (ah RANDOM ADDRESS HASH FUNCTIONS)
    key = "ec0234a357c8ad05341010a60a397d9b"
    aes_test = USE_AES(key)    
    encrypt = aes_test.encrypt_ext('00000000000000000000000000708194')
    #159d5fb7 2ebe2311 a48c1bdc c40dfbaa ==> 0dfbaa
    print(encrypt)
    '''

    
    #key = key[2:]
    #key = key + "00"
    #aes_test = USE_AES(key)
    #encrypt = aes_test.encrypt_ext(str(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'))
    #encrypt = aes_test.encrypt_ext('00112233445566778899aabbccddeeff')
    
    #key = "9bca350aad02577d2583b614eb3e3ae1"
    #key = "e13a3eeb14b683257d5702ad0a35ca9b"
    #aes_test = USE_AES(key)
    #encrypt = aes_test.encrypt_ext('0000000000000000000000000058fff6')
    #encrypt = aes_test.encrypt_ext('00000000000000000000000000e32856')
    #print(encrypt)
    
    f = open(filename, 'rb', True)
    i = 0
    while True:
        # 每次读取一个字符
        ch = f.read(1)
        # 如果没有读到数据，跳出循环
        if not ch: break
        # 输出ch
        key = key[2:]
        #print(binascii.b2a_hex(ch))
        key = key + str(binascii.b2a_hex(ch))[2:-1]
        aes_test = USE_AES(key)
        #encrypt = aes_test.encrypt_ext('00112233445566778899aabbccddeeff')
        #encrypt = aes_test.encrypt_ext('000000000000000000000000003bea5b')
        encrypt = aes_test.encrypt_ext('00000000000000000000000000237279')
        #encrypt = aes_test.encrypt_ext('0000000000000000000000000024017a')
        #encrypt = aes_test.encrypt_ext('000000000000000000000000005bea3b')
        check_result(encrypt)
        #i = i + 1
        #if i > 10: break
        #print(ch, end='')
    f.close()

    #print(encrypt)

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    