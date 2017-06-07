__author__ = 'YPS'
# -*- coding:utf-8 -*-
'''
欧拉函数：n的欧拉函数为小于n且于n互质的数的个数
欧拉定理：两个正整数a,n互质，φ(n)是n的欧拉函数,a的φ(n)次方被n除的余数为1。a^φ(n)%n=1，或者说，(a^φ(n)-1)%n=0
模反元素：如果两个正整数a和n互质，那么一定可以找到整数b，使得ab-1被n整除，或者说ab被n除的余数是1。b就叫做a的"模反元素"。
第一步，随机选择两个不相等的质数p和q。
第二步，计算p和q的乘积N。
第三步，计算n的欧拉函数φ(n)=r。
第四步，随机选择一个整数e，条件是1< e < φ(n)，且e与φ(n) 互质。
第五步，计算e对于φ(n)的模反元素d。
第六步，将n和e封装成公钥，n和d封装成私钥。
第七步，加密和解密
'''
import math
import random
from tkinter import *
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
from tkinter import messagebox


# 获得小于max_number的所有质数
def make_prime_number(max_number):
    prime = []
    for i in range(2, max_number):
        temp = 0
        sqrt_max_num = int(math.sqrt(i))+1
        for j in range(2,sqrt_max_num):
            if i % j == 0:
                temp = j
                break
        if temp == 0:
            prime.append(i)
    return prime

# 获得公钥和私钥
def make_rsa_key():
    prime = make_prime_number(500)
    pri_len = len(prime)
    # 随机选择两个不相等的质数p和q
    p = prime[random.randint(0, pri_len)]
    q = prime[random.randint(0, pri_len)]
    # 计算p和q的乘积N
    N = p*q
    # 计算n的欧拉函数r
    r = (p-1)*(q-1)
    r_prime = make_prime_number(r)
    r_pre_len = len(r_prime)
    # 随机选择一个整数e，条件是1< e < r，且e与r互质
    e = r_prime[random.randint(0, r_pre_len)]
    # 计算e对于φ(n)的模反元素d
    d = 0
    for d0 in range(2, r):
        if e*d0 % r == 1:
            d = d0
            break
    # 返回公钥(N,e)私钥(N,d)
    return [[N,e],[N,d]]

# 加密函数
def encrypt(pub_key,message):
    N,e = pub_key
    return (message**e)%N

# 解密函数
def decrypt(pri_key,encry):
    N,d = pri_key
    return (encry**d)%N

def encryptmakemessage(message, key):
    rsa_key = tuple(eval((key)))
    pub_key,pri_key = rsa_key
    encrypt_message = [encrypt(pub_key,ord(x)) for x in message]
    encrypt_show=",".join([str(x) for x in encrypt_message])
    print(encrypt_message)
    print(encrypt_show)
    return encrypt_show

def decryptmakemessage(encrypt_message, key):
    rsa_key = tuple(eval((key)))
    pub_key,pri_key = rsa_key
    temp = encrypt_message.split(',')
    for i in range(len(temp)):
        temp[i] = int(temp[i])
    print(temp)
    decrypt_message = [chr(decrypt(pri_key,int(x))) for x in temp]
    decrypt_show="".join(decrypt_message)
    print(decrypt_show)
    return decrypt_show

def encryptinputmessage(message, key):
    pub_key = tuple(eval((key)))
    encrypt_message = [encrypt(pub_key,ord(x)) for x in message]
    encrypt_show=",".join([str(x) for x in encrypt_message])
    print(encrypt_message)
    print(encrypt_show)
    return encrypt_show

def decryptinputmessage(encrypt_message, key):
    pri_key = tuple(eval((key)))
    temp = encrypt_message.split(',')
    for i in range(len(temp)):
        temp[i] = int(temp[i])
    print(temp)
    decrypt_message = [chr(decrypt(pri_key,int(x))) for x in temp]
    decrypt_show="".join(decrypt_message)
    print(decrypt_show)
    return decrypt_show

def main(message, key):
    # rsa_key = tuple(eval((key)))
    # pub_key,pri_key = rsa_key
    pri_key = (44339,35689)
    # encrypt_message = [encrypt(pub_key,ord(x)) for x in message]
    encrypt_message = [15875, 22319, 22018, 32148]
    decrypt_message = [chr(decrypt(pri_key,x)) for x in encrypt_message]

    # encrypt_show=",".join([str(x) for x in encrypt_message])
    decrypt_show="".join(decrypt_message)

    # print(encrypt_show)
    print(decrypt_show)


# AES算法类
class AEScrypt():
    def __init__(self, key, iv):
        # 初始化秘钥跟偏移量
        self.key = key
        self.iv = iv
        # 确定AES加解密模式，秘钥长度
        self.mode = AES.MODE_CBC
        self.BS = AES.block_size
        # padding算法
        # 用于判断数据长度是否为16字节块的整数倍，从而进行适当的Padding，这里的关键是利用'%'运算判断是否是16字节的整数倍，然后在尾部追加(16-x)个填充字符；
        self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
        self.unpad = lambda s: s[0:-ord(s[-1])]

    def encrypt(self, text):
        text = self.pad(text)
        # 生成了加密时需要的实际密码，主要使用了AES.new(key, AES.MODE_CBC,iv)函数
        self.obj1 = AES.new(self.key, self.mode, self.iv)
        self.ciphertext = self.obj1.encrypt(text)
        # 把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)

    #使用密钥先对密文解密，解密后再同初始向量异或得到明文。
    def decrypt(self, text):
        self.obj2 = AES.new(self.key, self.mode, self.iv)
        plain_text  = self.obj2.decrypt(a2b_hex(text))
        return self.unpad(plain_text.decode(encoding='utf-8'))

def AESmain():
    pc = AEScrypt()
    e = pc.encrypt("nihao")
    print(e.decode(encoding='utf-8'))
    d = pc.decrypt(e.decode(encoding='utf-8'))
    print(d)

def showRSAhelp():
    messagebox.showinfo('RSAHelp', '生成秘钥会自动生成一组公钥和私钥用来测试，这时可以直接输入明文密文来加密解密\n'
                                   '需要加密时，直接输入明文和公钥，点击使用输入的公钥加密\n'
                                   '需要解密时，输入密文和私钥，点击使用输入的私钥解密')

def showAEShelp():
    messagebox.showinfo('AESHelp', '1.输入秘钥（16，24,32位）偏移量（16位）；'
                                   '2.点击初始化；3.输入明文；4.加密；5.复制密文到解密框；6.解密；\n注：每次更改秘钥和偏移量后需再点击初始化')

global pc
def initAESclass(key, iv):
    global pc
    pc = AEScrypt(key, iv)


# 图形界面
root = Tk()

root.title('对称&非对称密码算法加解密')
# 加密的消息
message = StringVar()
# 公钥和私钥
key = StringVar()
# 输入的公钥
pub_key = StringVar()
# 输入的私钥
pri_key = StringVar()
# 加密后的密文
encrypt_message = StringVar()
# 待解密的密文
decrypt_message = StringVar()
# 解密后的密文
decrypted_message = StringVar()
RSA = LabelFrame(root, text="RSA")
RSA.grid(row=4, column=0)
Label(root, text="非对称RSA加解密", font=('微软雅黑', 18)).grid(row=3, column=0)
Label(RSA, text="秘钥对({公钥} {私钥})：", width=20).grid(row=1, column=0)
Label(RSA, textvariable=key, width=20).grid(row=1, column=1)
Button(RSA, text="生成密钥", width=15, command=lambda: key.set(make_rsa_key())).grid(row=1, column=2)
Label(RSA, text="输入要加密的消息:", width=20).grid(row=2, column=0)
Entry(RSA, textvariable=message, width=20).grid(row=2, column=1)
Button(RSA, text="帮助", width=15, command=showRSAhelp).grid(row=2, column=2)
Button(RSA, text="生成的公钥加密", width=15, command=lambda: encrypt_message.set(encryptmakemessage(message.get(),key.get()))).grid(row=3,column=2)
Label(RSA, text="输入RSA公钥:", width=20).grid(row=3, column=0)
Entry(RSA, textvariable=pub_key, width=20).grid(row=3, column=1)
Button(RSA, text="输入的公钥加密", width=15, command=lambda: encrypt_message.set(encryptinputmessage(message.get(),pub_key.get()))).grid(row=4,column=2)
Label(RSA, text="加密后的密文为：", width=20).grid(row=4, column=0)
Entry(RSA, textvariable=encrypt_message, width=20).grid(row=4, column=1)
Label(RSA, text="输入要解密的密文:", width=20).grid(row=5, column=0)
Entry(RSA, textvariable=decrypt_message, width=20).grid(row=5, column=1)
Button(RSA, text="生成的秘钥解密", width=15, command=lambda: decrypted_message.set(decryptmakemessage(decrypt_message.get(),key.get()))).grid(row=5,column=2)
Label(RSA, text="输入RSA私钥:", width=20).grid(row=6, column=0)
Entry(RSA, textvariable=pri_key, width=20).grid(row=6, column=1)
Button(RSA, text="输入的秘钥解密", width=15, command=lambda: decrypted_message.set(decryptinputmessage(decrypt_message.get(),pri_key.get()))).grid(row=6,column=2)
Label(RSA, text="解密后的明文为：", width=20).grid(row=7, column=0)
Entry(RSA, textvariable=decrypted_message, width=20).grid(row=7, column=1)
Button(RSA, text="关闭", width=15, command=root.quit).grid(row=7, column=2)




# 加密的消息
Amessage = StringVar()
# 加密后的密文
Aencrypt_message = StringVar()
# 待解密的密文
Adecrypt_message = StringVar()
# 解密后的密文
Adecrypted_message = StringVar()
# 秘钥
Akey = StringVar()
# 向量偏移量
Aiv = StringVar()

AESx = LabelFrame(root, text="AES")
AESx.grid(row=1, column=0)
Akey.set('1234567890123456')
Aiv.set('This is an IV456')
Label(root, text="对称AES加解密", font=('微软雅黑', 18)).grid(row=0, column=0)
Label(AESx, text="输入AES秘钥:", width=20).grid(row=9, column=0)
Entry(AESx, textvariable=Akey, width=20).grid(row=9, column=1)
Label(AESx, text="偏移量必须是16位", width=15).grid(row=9, column=2)
Label(AESx, text="输入AES偏移量:", width=20).grid(row=10, column=0)
Entry(AESx, textvariable=Aiv, width=20).grid(row=10, column=1)
Button(AESx, text="初始化", width=15, command=lambda: initAESclass(Akey.get(), Aiv.get())).grid(row=10,column=2)
Label(AESx, text="输入要加密的消息:", width=20).grid(row=11, column=0)
Entry(AESx, textvariable=Amessage, width=20).grid(row=11, column=1)
Button(AESx, text="加密", width=15, command=lambda: Aencrypt_message.set((pc.encrypt(Amessage.get())).decode(encoding='utf-8'))).grid(row=11,column=2)
Label(AESx, text="输入要解密的密文:", width=20).grid(row=12, column=0)
Entry(AESx, textvariable=Adecrypt_message, width=20).grid(row=12, column=1)
Button(AESx, text="解密", width=15, command=lambda: Adecrypted_message.set(pc.decrypt(Adecrypt_message.get()))).grid(row=12,column=2)
Label(AESx, text="加密后的密文为：", width=20).grid(row=13, column=0)
Entry(AESx, textvariable=Aencrypt_message, width=20).grid(row=13, column=1)
Label(AESx, text="解密后的明文为：", width=20).grid(row=14, column=0)
Entry(AESx, textvariable=Adecrypted_message, width=20).grid(row=14, column=1)
Button(AESx, text="帮助", width=15, command=showAEShelp).grid(row=13, column=2)
Label(AESx, text="").grid(row=14, column=3)
Label(root, text="").grid(row=2, column=0)
root.mainloop()