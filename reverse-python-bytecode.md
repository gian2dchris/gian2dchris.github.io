# REV300: Python reversing 300pts

---

Hint: *Have you ever seen Python bytecode? Well... it was about time! Python version: 2.7, Flag format: CTF{32-hex}*

The challenge has no backend server only 2 files to download. A text file containing python byte code and the encrypted flag. It looks like we have to reverse an encryption scheme.

```bash
$ ls -l
total 12
-rw-r--r-- 1 root root 6256 Dec 11 21:34 chall.txt
-rw-r--r-- 1 root root   37 Dec 11 21:34 flag_enc
```

Examining the head of `chall.txt` , we see what seems to be a module import followed by some function calls.

```bash
head chall.txt 
  2           0 LOAD_CONST               1 (-1)
              3 LOAD_CONST               0 (None)
              6 IMPORT_NAME              0 (marshal)
              9 STORE_FAST               0 (marshal)

  3          12 LOAD_FAST                0 (marshal)
             15 LOAD_ATTR                1 (loads)
             18 LOAD_CONST               2 ('c\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00C\x00\x00\x00s\x08\x00\x00\x00|\x00\x00|\x01\x00AS(\x01\x00\x00\x00N(\x00\x00\x00\x00(\x02\x00\x00\x00t\x01\x00\x00\x00at\x01\x00\x00\x00b(\x00\x00\x00\x00(\x00\x00\x00\x00s\x07\x00\x00\x00<stdin>t\x08\x00\x00\x00<lambda>\x01\x00\x00\x00s\x00\x00\x00\x00')
             21 CALL_FUNCTION            1
             24 STORE_FAST               1 (l1)
```

 I had no previous experience with python byte code so i wrote a simple script in order to verify this by copying the serialized data and trying to replicate it using marshal and dis modules.

```python
def module_import():
    import marshal
    l1 = marshal.loads('c\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00C\x00\x00\x00s\x08\x00\x00\x00|\x00\x00|\x01\x00AS(\x01\x00\x00\x00N(\x00\x00\x00\x00(\x02\x00\x00\x00t\x01\x00\x00\x00at\x01\x00\x00\x00b(\x00\x00\x00\x00(\x00\x00\x00\x00s\x07\x00\x00\x00<stdin>t\x08\x00\x00\x00<lambda>\x01\x00\x00\x00s\x00\x00\x00\x00')

import dis
dis.dis(mod_imp)
```

The output of our script seems pretty similar, so we are on the right track.

```bash
  3           0 LOAD_CONST               1 (-1)
              3 LOAD_CONST               0 (None)
              6 IMPORT_NAME              0 (marshal)
              9 STORE_FAST               0 (marshal)

  6          12 LOAD_FAST                0 (marshal)
             15 LOAD_ATTR                1 (loads)
             18 LOAD_CONST               2 ('c\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00C\x00\x00\x00s\x08\x00\x00\x00|\x00\x00|\x01\x00AS(\x01\x00\x00\x00N(\x00\x00\x00\x00(\x02\x00\x00\x00t\x01\x00\x00\x00at\x01\x00\x00\x00b(\x00\x00\x00\x00(\x00\x00\x00\x00s\x07\x00\x00\x00<stdin>t\x08\x00\x00\x00<lambda>\x01\x00\x00\x00s\x00\x00\x00\x00')
             21 CALL_FUNCTION            1
             24 STORE_FAST               1 (l1)
             27 LOAD_CONST               0 (None)
             30 RETURN_VALUE
```

The `chall.txt` continues with a couple of [lamda](http://book.pythontips.com/en/latest/lambdas.html) type deserializations as shown below, which we replicate the same way.

```bash
>>> l1  = marshal.loads('c\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00C\x00\x00\x00s\x08\x00\x00\x00|\x00\x00|\x01\x00AS(\x01\x00\x00\x00N(\x00\x00\x00\x00(\x02\x00\x00\x00t\x01\x00\x00\x00at\x01\x00\x00\x00b(\x00\x00\x00\x00(\x00\x00\x00\x00s\x07\x00\x00\x00<stdin>t\x08\x00\x00\x00<lambda>\x01\x00\x00\x00s\x00\x00\x00\x00')
>>> l2 = marshal.loads('c\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00C\x00\x00\x00s\x08\x00\x00\x00|\x00\x00|\x01\x00\x17S(\x01\x00\x00\x00N(\x00\x00\x00\x00(\x02\x00\x00\x00t\x01\x00\x00\x00at\x01\x00\x00\x00b(\x00\x00\x00\x00(\x00\x00\x00\x00s\x07\x00\x00\x00<stdin>t\x08\x00\x00\x00<lambda>\x01\x00\x00\x00s\x00\x00\x00\x00')
>>> l3 = marshal.loads('c\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00C\x00\x00\x00s\x04\x00\x00\x00d\x01\x00S(\x02\x00\x00\x00Nt%\x00\x00\x00Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1A(\x00\x00\x00\x00(\x00\x00\x00\x00(\x00\x00\x00\x00(\x00\x00\x00\x00s\x07\x00\x00\x00<stdin>t\x08\x00\x00\x00<lambda>\x01\x00\x00\x00s\x00\x00\x00\x00')
>>> l4 = marshal.loads('c\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00C\x00\x00\x00s\x07\x00\x00\x00t\x00\x00\x83\x00\x00S(\x01\x00\x00\x00N(\x01\x00\x00\x00t\t\x00\x00\x00raw_input(\x00\x00\x00\x00(\x00\x00\x00\x00(\x00\x00\x00\x00s\x07\x00\x00\x00<stdin>t\x08\x00\x00\x00<lambda>\x01\x00\x00\x00s\x00\x00\x00\x00')

>>> type(l2)
<type 'code'>
```

Ok, so it seems this variables are lambdas, but what exactly are lambdas. According to python documentation lambdas are one line functions also known as anonymous functions in some other languages. Essentially code ! But what does this code do ?

```python
>>> dis.dis(l1)
  1           0 LOAD_FAST                0 (a)
              3 LOAD_FAST                1 (b)
              6 BINARY_XOR          
              7 RETURN_VALUE        
>>> dis.dis(l2)
  1           0 LOAD_FAST                0 (a)
              3 LOAD_FAST                1 (b)
              6 BINARY_ADD          
              7 RETURN_VALUE        
>>> dis.dis(l3)
  1           0 LOAD_CONST               1 ('Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1A')
              3 RETURN_VALUE        
>>> dis.dis(l4)
  1           0 LOAD_GLOBAL              0 (raw_input)
              3 CALL_FUNCTION            0
              6 RETURN_VALUE
```

Byte code slowly starts to feel comfortable ! So far we know:

-  l1: xor(a,b)
- l2: add(a,b)
- l3: loads a string: 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1A'
- l4: call raw_input()

Let's continue with `chall.txt`. 

```bash
  7          72 LOAD_CONST               6 (<code object <lambda> at 0x7f42c16fc8b0, file "chall.py", line 7>)
             75 MAKE_FUNCTION            0
             78 STORE_FAST               5 (dummy)

  8          81 LOAD_FAST                4 (l4)
             84 LOAD_FAST                5 (dummy)
             87 STORE_ATTR               2 (func_code)

  9          90 LOAD_FAST                5 (dummy)
             93 CALL_FUNCTION            0
             96 STORE_FAST               6 (flag)

 10          99 LOAD_CONST               7 ('')
            102 STORE_FAST               7 (out)

 11         105 SETUP_LOOP             162 (to 270)
            108 LOAD_GLOBAL              3 (range)
            111 LOAD_GLOBAL              4 (len)
            114 LOAD_FAST                6 (flag)
            117 CALL_FUNCTION            1
            120 CALL_FUNCTION            1
            123 GET_ITER            
            124 FOR_ITER               142 (to 269)
            127 STORE_FAST               8 (i)
```

Sections 7 to 9 seem to load the  *key_string* in *dummy* variable and the unencrypted flag in *flag* variable. This is probably the reason we where given a text file and not `chall.pyc`. Section 10 sets and empty python string *out*, and finally section 11 initiates a loop. The rest of `chall.txt` contains easy to understand, python bytecode that executes byte operations performed on the flag, using the lambdas described above. Finally the encrypted flag is written in the flag_enc file.

The encryption process (not using lambdas) is the following:

```python
flag = b'CTF{flag}'
dummy = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1A'
flag_enc = ''

for i in range(len(flag)):
    o1 = ord(flag[i])
    o2 = ord(dummy[i])
    o3 = o1 ^ o2
    o4 =o3 + 20
    o5 = o4 ^ 90
    flag_enc += chr(o5^1)

print(flag_enc)
```

So if we reverse the operations we can decrypt the flag.

```python
f = open('flag_enc','rb')
flag_enc = f.read()
f.close()
dummy = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1A'

for i in range(len(flag_enc)):
    o5 = ord(flag_enc[i])^1
    o2 = ord(dummy[i])
    o4 = o5 ^ 90
    o3 = o4 - 20
    o1 = o3 ^ o2
    out += chr(o1)

print("flag: " + out)
```

```bash
flag: CTF{b853e27db2e3ae06794d32a53f6ee356}
```

## References

[Python bytecode intro](https://opensource.com/article/18/4/introduction-python-bytecode)

[python-bytecode-instructions](https://docs.python.org/3.5/library/dis.html#python-bytecode-instructions)

[https://www.synopsys.com/blogs/software-security/understanding-python-bytecode/](https://www.synopsys.com/blogs/software-security/understanding-python-bytecode/)



[Back](https://gian2dchris.github.io/)