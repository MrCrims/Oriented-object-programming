import hashlib
import random
import sympy
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

mod_p = 165713
B_private = 12

g = sympy.primitive_root(mod_p)
Y_beta = (g**B_private)%mod_p

def ElGmal_encrypt(message):
    k = random.randint(2, mod_p - 2)
    K = Y_beta**k % mod_p
    enc_mess = []
    for i in [0,4,8,12]:
        enc_mess.append(str((int(message[i:i+4])*K)%mod_p))

    enc_mess.append(str((g ** k) % mod_p))#包含g的信息放在后面
    return enc_mess

def ElGmal_decrypt(message):
    key = int(message[4])
    K = key**B_private % mod_p
    K_ = sympy.mod_inverse(K,mod_p)#K的逆元
    ori_mess = ""
    for i in message[0:4]:
        ori_mess += str((int(i)*K_)%mod_p)
    print(ori_mess)
    return ori_mess

class User:
    def __init__(self, username, password):
        self.username = username
        md5 = hashlib.md5(password.encode())
        self.password = md5.hexdigest()  # hexdigest是十六进制数据字符串值

    def check_password(self, password):  # 验证密码是否正确
        md5 = hashlib.md5(password.encode())
        if md5.hexdigest() == self.password:
            return ["The password is right",1]
        else:
            return ["You have input in wrong password",0]

def add_to_16(text):
    if len(text.encode('utf-8')) % 16:
        add = 16 - (len(text.encode('utf-8')) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text.encode('utf-8')


# 加密函数
def AES_encrypt(text):
    key = input("Please input your 16Bytes key:").encode('utf-8')
    key_encry = ElGmal_encrypt(key)
    mode = AES.MODE_ECB
    text = add_to_16(text)
    cryptos = AES.new(key, mode)

    cipher_text = cryptos.encrypt(text)
    return [b2a_hex(cipher_text),key_encry]


# 解密后，去掉补足的空格用strip() 去掉
def AES_decrypt(text):
    key = ElGmal_decrypt(text[1]).encode('utf-8')
    mode = AES.MODE_ECB
    cryptor = AES.new(key, mode)
    plain_text = cryptor.decrypt(a2b_hex(text[0]))
    return bytes.decode(plain_text).rstrip('\0')


print("Before you use this please complete the registration")
username = input("Please input your username:")
password = input("Please input your password:")
user = User(username,password)
print("You have finished the registration , now you can encode your message.")
message = input("Please input your message:")
Ciph = AES_encrypt(message)
print(Ciph[0])
password = input("Before you decode this ciphertext , we need to check your password:")
res = user.check_password(password)
if res[1] == 1:
    print(res[0])
    Message = AES_decrypt(Ciph)
    print(Message)
else :
    print(res[0])