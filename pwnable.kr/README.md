# Writeup for 'crypto1' on pwnable.kr

This repository serves as a writeup for the 'crypto1' ctf on pwnable.kr. The program accepts an ID and a password.

### Available files

After logging in with the 'crypto1' user, we see 1 readme and 2 python files.

##### client.py
```python
#!/usr/bin/python2
from Crypto.Cipher import AES
import base64
import os, sys
import xmlrpclib
rpc = xmlrpclib.ServerProxy("http://localhost:9100/")

BLOCK_SIZE = 16
PADDING = '\x00'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: c.encrypt(pad(s)).encode('hex')
DecodeAES = lambda c, e: c.decrypt(e.decode('hex'))

# server's secrets
key = 'erased'
iv = '\x5c'*BLOCK_SIZE
cookie = 'erased'

# guest / a488ff12949b87e5c93d489c27217486702b179c060399adf36fc3bc1f5425ec
def sanitize(arg):
        for c in arg:
                if c not in '1234567890abcdefghijklmnopqrstuvwxyz-_':
                        return False
        return True

def AES128_CBC(msg):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return EncodeAES(cipher, msg)

def request_auth(id, pw):
        packet = '{0}-{1}-{2}'.format(id, pw, cookie)
        e_packet = AES128_CBC(packet)
        print 'sending encrypted data ({0})'.format(e_packet)
        sys.stdout.flush()
        return rpc.authenticate(e_packet)

if __name__ == '__main__':
        print '---------------------------------------------------'
        print '-       PWNABLE.KR secure RPC login system        -'
        print '---------------------------------------------------'
        print ''
        print 'Input your ID'
        sys.stdout.flush()
        id = raw_input()
        print 'Input your PW'
        sys.stdout.flush()
        pw = raw_input()

        if sanitize(id) == False or sanitize(pw) == False:
                print 'format error'
                sys.stdout.flush()
                os._exit(0)

        cred = request_auth(id, pw)

        if cred==0 :
                print 'you are not authenticated user'
                sys.stdout.flush()
                os._exit(0)
        if cred==1 :
                print 'hi guest, login as admin'
                sys.stdout.flush()
                os._exit(0)

        print 'hi admin, here is your flag'
        print open('flag').read()
        sys.stdout.flush()
```

##### server.py:

```python
#!/usr/bin/python2
import xmlrpclib, hashlib
from SimpleXMLRPCServer import SimpleXMLRPCServer
from Crypto.Cipher import AES
import os, sys

BLOCK_SIZE = 16
PADDING = '\x00'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: c.encrypt(pad(s)).encode('hex')
DecodeAES = lambda c, e: c.decrypt(e.decode('hex'))

# server's secrets
key = 'erased'
iv = '\x5c'*BLOCK_SIZE
cookie = 'erased'

def AES128_CBC(msg):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return DecodeAES(cipher, msg).rstrip(PADDING)

def authenticate(e_packet):
    packet = AES128_CBC(e_packet)

    id = packet.split('-')[0]
    pw = packet.split('-')[1]

    if packet.split('-')[2] != cookie:
        return 0
    if hashlib.sha256(id+cookie).hexdigest() == pw and id == 'guest':
        return 1
    if hashlib.sha256(id+cookie).hexdigest() == pw and id == 'admin':
        return 2
    return 0

server = SimpleXMLRPCServer(("localhost", 9100))
print "Listening on port 9100..."
server.register_function(authenticate, "authenticate")
server.serve_forever()
```

We can see that client.py accepts some input which is combined, encrypted with AES and then sent to the server. server.py then receives that, decrypts it and checks if the password is correct. So all we need to do is to find the correct password of the 'admin'.

### Finding the password

A comment in client.py provides us with the password to the 'guest' user. This works but it does not return the flag because we need to login as 'admin'. This is the function responsible for authentication.

```python
def authenticate(e_packet):
    packet = AES128_CBC(e_packet)

    id = packet.split('-')[0]
    pw = packet.split('-')[1]

    if packet.split('-')[2] != cookie:
        return 0
    if hashlib.sha256(id+cookie).hexdigest() == pw and id == 'guest':
        return 1
    if hashlib.sha256(id+cookie).hexdigest() == pw and id == 'admin':
        return 2
    return 0
```

This function shows us that the password is equal to `hashlib.sha256(id+cookie).hexdigest()`. We can compute this hash ourselves as long as we know the values `id` and `cookie`, so finding the password should be simple. There is just one problem. While we have full control over `id`, we have absolutely no idea what `cookie` is. This variable is hard coded in both client.py and server.py but it is redacted. 

### Finding cookie

We need to somehow find the value of `cookie`. Let's take a look at how we are sending our inputs.

```python
def request_auth(id, pw):
        packet = '{0}-{1}-{2}'.format(id, pw, cookie)
        e_packet = AES128_CBC(packet)
        print 'sending encrypted data ({0})'.format(e_packet)
        sys.stdout.flush()
        return rpc.authenticate(e_packet)
```

Here we can see that the string to be encrypted is structured like this: `<id>-<pw>-<cookie>` where we have full control over `id` and `pw` but `cookie` is unknown.
This is then encrypted and sent to server.py. Interestingly, the encrypted data is also printed. This should be good news. The ciphertext which includes `cookie` is leaked. So we have a partially controlled plaintext and we can always find out the corresponding ciphertext. Is there any way to find the unknown part of the plaintext under these circumstances? Well, let's take a look at the AES implementation to answer that.

### The AES implementation

```python
# server's secrets
key = 'erased'
iv = '\x5c'*BLOCK_SIZE
cookie = 'erased'
```
```python
cipher = AES.new(key, AES.MODE_CBC, iv)
```

We can see that the key is redacted. We do know the IV which is basically another input parameter but that doesn't really matter because it is deemed cryptographically infeasible to break AES without knowing the key. This means that we have no way of finding the plaintext, even if the program is leaking the ciphertext, right? WRONG!
The AES implementation is using CBC mode and reuses the same IV which opens a potential attack vector. 

### Block cipher modes

AES is a block cipher which means that the plaintext is split into blocks of a set block size. The mode of operation then determines how these blocks are encrypted. For example in ECB mode, all blocks are encrypted independently using the same key.  
In our case, CBC mode is used which means that the plaintext of each block is first XORed with the ciphertext of the previous block and then encrypted. The very first block does not have a previous block, so it uses an IV (Initialization vector) instead. This IV does not have to be secret but it should be randomized so that the same plaintext results in different ciphertexts to be unpredictable. In our case, the IV is hard coded though, so the ciphertext of every block depends only on the previous blocks. This is a potential attack vector.

### The attack

client.py serves as our oracle which means that we can give it some plaintext and it gives us back the corresponding ciphertext. Without an oracle, this attack is not possible. What we can do is choose our inputs in such a way that the first byte of `cookie` is placed at the last byte of a block. We then record the ciphertext of that block. Next, we give the same plaintext to the oracle with the only difference being that the final byte of that block is now filled with any byte we desire. If the produced ciphertext is the same as the recorded ciphertext, we know that this block and therefore we found one byte belonging to `cookie`. If the ciphertexts do not match, we simply try again until we find a match. We then repeat this with the next byte and find `cookie` byte to byte.  
This attack is automated in exploit.py:
```python
from pwn import *
import hashlib


BLOCK_SIZE = 16
CIPHER_TEXT_START = 24

# we compare the 4th block
BLOCK_START = CIPHER_TEXT_START + 3 * 2 * BLOCK_SIZE
BLOCK_END = CIPHER_TEXT_START + 4 * 2 * BLOCK_SIZE
# multiplied by 2 because the ciphertexts are double the size of the plaintexts
# because of hex encoding

characters = '0123456789abcdefghijklmnopqrstuvwxyz_-'

cookie = ''

i = 0
while True:
    p = remote('127.0.0.1', 9006)

    id_ = b'0'
    pw = b'-' * (BLOCK_SIZE * 4 - 4 - i)
    # plaintext will be <id_>-<pw>-<cookie>

    p.recvuntil(b'ID\n')
    p.sendline(id_)
    p.recvline()
    p.sendline(pw)

    line = p.recvline()
  
    target_block = line[BLOCK_START:BLOCK_END]

    p.close()

    found = False
    for character in characters:
        p = remote('127.0.0.1', 9006)

        id_ = b'0'
        pw = b'-' * (BLOCK_SIZE * 4 - 3 -i)
        pw += cookie.encode() + character.encode()
        # plaintext will be <id_>-<pw>-<cookie>

        p.recvuntil(b'ID\n')
        p.sendline(id_)
        p.recvline()    
        p.sendline(pw)
    
        line = p.recvline()
        block = line[BLOCK_START:BLOCK_END]

        p.close()
        
        if block == target_block:
            cookie += character
            found = True
            break

    if not found: break
    
    i += 1
    print(cookie)

guest_pw = hashlib.sha256(('guest' + cookie).encode()).hexdigest() 
admin_pw = hashlib.sha256(('admin' + cookie).encode()).hexdigest() 

print(f'cookie: {cookie}')
print('\nCredentials:')
print(f'guest:{guest_pw}')
print(f'admin:{admin_pw}')
```


