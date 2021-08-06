# VirSecCon CTF "Scripting Challenges"


Here, I will explain about all the challenges that I solved from scriting category.
<!--more-->

---

## Introduction

Scripting is a programming language for a special run-time that automates the execution of tasks; tasks could alternatively be executed one-by-one by a human operator. We people think there is no any difference in between coding and scripting but there is a saying :-

" All scripting is coding, but not all coding is scripting. " 

During VirSecCon CTF there was also Scripting Category which helped me to make my scripting to get the flag. Here I used python scripting and solved the challenges.

## Challenges

### 1. 2048

#### Description [75]  
cGx6aGVscG1l=> plzhelpme (base64 decode)

File: [2048.zip](public/files/2048.zip)

Solution: As challenge is zipped, I unzipped that file and got the 2048 file .

```
root@gr4n173:# cat 2048
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVjAxV2JETlhhMUpUVmpBeFYySkVU
bGhoTVVwVVZtcEJlRll5U2tWVQpiR2hvVFZWd1ZWWnRjRUpsUmxsNVUydFdWUXBpUjJodlZGWldk
MVpXV25SalJVcHNVbXhzTlZVeWRGZFdVWEJwVWpKb2RsWkdXbGRrCk1WcFhWMjVTYWxKVmNITlZi
WGh6VGxaVmVXUkdaRmRWV0VKd1ZXcEtiMlJzV2tkWGJHUnJDazFXY0ZoV01qVlRZV3hLVm1OSVRs
WmkKV0doNlZHeGFWbVZYVWtkYVJtUldWMFZLZDFaWGNFdGlNbEp6VjJ0a1dHSkhVbkpEYXpGWFkw
Wm9WMDFxVmxSWlYzaExWbTFPU1ZScwpXbWtLVjBkb05sWkhlR0ZXYlZaWVZXdGtZVkp0VWxkV01G
WkxaREZhV0dORmRHbE5iRXA2VmpKMGExZEhTa2hWYmtwRVlYcEdXRmt3CldtOVdNREZ4Vm14U1ds
WXphRXhXYlRGUFUxWlNjd3BYYld0TFZqQmtiMDVzV2tobFIwWlhZbFphV1ZaWGRHdFpWa3AwVld4
a1YwMUcKV2t4YVJFWmhWMGRPUm1SSGJFNWlSWEEyVm1wS01HRXhaRWhUYTJoV1ltdHdSVmxZY0Vk
WFJtdDNDbGR0T1ZkTlJFWjRWbTE0VTFkcwpXWHBoUlhoWFlsUkdVRlV4V2xOamQzQllZbGQwVEZa
cVFtdGlNRFZ6VjJ0b2JGSXdXbGhaYkZwaFYxWmFXR1JIZEZwV2EzQXdWbGQ0CmExWXdNVWNLVjJ0
NFlWSkZXbWhXTUdSUFVtMVNTR0pGTldsU1dFRXlWbTF3UzAxSFJYaGFSV2hVWVRKb1YxbHRkSGRT
Vm14WlkwVmsKV0ZKdGRETkRiR1IwVDFaa1RsSkZXalJXYlRFMFZURmtjd3BYV0hCb1VsaG9XRmxz
VWtkVlJsVjRWMnhPYW1RelFsbFpiR1F3VkVaYQpjVkZ0ZEdsTlJGWjZWakowYjJKR1NY........==
```
this indicate the file ASCII text and I tried encoding all many times and I got the flag after 32 decoding. This way I got the 75 points.

```
root@gr4n173:~# cat 2048(32)
LCSC{i_hope_you_didnt_use_asciitohex.com}
```

### 2. Quick Run

#### Description [75]
You gotta go fast!

Download the file below.

File: [quick_run.zip](public/files/quick_run.zip)

Solution: As I unzipped that file I got 31 QR-code images so I wrote a simple script in python to decode this image for that I used `pyzbar` module `Python Imaging Library(PIL)` .

```
root@gr4n173:~#cat bardecode.py
from PIL import Image
from pyzbar.pyzbar import decode
#!/bin/python3
res = []
for i in range(0,34):
        img = Image.open("quick_run/"+str(i)+".png")
        data = decode(img)
        res.append(data[0].data)
        img.close()
        print(chr(int(data[0].data)))
```
Then I run the script and got the flag with 75 points added.

```
root@gr4n173:~# python3 bardecode.py
L                                                                                                                                                     
L                                                                                                                                                     
S                                                                                                                                                     
{                                                                                                                                                     
z
b
a
r
i
m
g
_
m
a
k
e
s
_
q
r
c
o
d
e
s
_
e
a
s
y
}
```

### 3. Pincode

#### Description [75]
This service needs a 4 digit pincode to authenticate... can you help me figure it out!??

Connect with:

`nc jh2i.com 50031`

Solution: As the server require 4 digit pincode so only way to enter the digit is from 0000 to 9999 so I wrote a simple script in python.

```
roo@gr4n173:~# cat pincode.py
from __future__ import print_function
from pwn import *

pin = 0
while pin < 9999:
    print(pin,end="")
    r = remote('jh2i.com', 50031)
    r.recvuntil(":")
    r.send(str("%04d" % (pin)))
    hashi = r.recvline()
    print(hashi)
    
    r.close()
    if("INCORRECT!" not in hashi):
        break
    pin+=1
```
After 37 step I got the flag and 75 points was added.

```
......                                                                                             
[*] Closed connection to jh2i.com port 50031

37[+] Opening connection to jh2i.com on port 50031: Done  
CORRECT! Here is your flag: LLS{for_i_in_0000_to_9999}                                                                                                
                                                                                                                                                      
[*] Closed connection to jh2i.com port 50031 
```

### 4. Loopback
#### Description [100]
Hello? Hello? Oh hello! Oh hello!

Download the file below.

File: [lookback.zip](public/files/loopback.zip)

Solution: As I unzipped that file I got the loopback.pcap file so I used the tshark tool to analyze the `.pcap` file and wrote a simple python script to analyze the raw file and finally I got the flag.

```
root@gr4n173:~#tshark -r loopback.pcap -T fields -e data > raw.txt

```
```
root@gr4n17:~#cat loopback.py
#!/bin/python3
#python loopback.py > result.txt
from __future__ import print_function
import binascii
import sys
import string
data = open("raw.txt",'r').read().splitlines()

chars = string.ascii_letters + string.digits + string.punctuation

res = ''
i=0
for a in data:
    decoded = a.decode("hex")[8:].strip()
    try:
        if(decoded[0] in chars):
            res+=decoded[0]
        i+=1
    except IndexError as identifier:
        pass

print(res)
```

```
Flag
	 LLSS{icmp_is_the_protocol_for_me}

```

### 5. Grammer

#### Description [125]
It’s only one letter away!

Connect with:

`nc jh2i.com 50012`

Solution: As the	server ask for flag I made a simple python script to brute-force the correct flag containing alphabet and symbols.

```
root@gr4n173:~#cat grammer.py
from __future__ import print_function
from pwn import *
import string
flag = "LLS{"
r = remote('jh2i.com', 50012)

chars = string.ascii_letters + string.digits + string.punctuation
print(chars)
is_first = True
while("}" not in flag):
    print("FLAG = ",flag)
    #print("TRY.. ",end="")
    if is_first :
        r.recvuntil(">")
    for char in chars:
        is_first = False
        print(char,end="")
        r.send(flag + char)
        lines = r.recvuntil('>').split("\n")
        #print(lines)
        if("CORRECT" in lines[-3]):
            #print(" OK ",end="")
            flag+=char
            break
        else:
            #print(" FALSE ",end="")
            pass
    print("")

print("FINAL FLAG = ",flag)
```
After running my script I got the flag and 125 points was added.

```
........
abcdefghijklm                                                                                                                                         
FLAG =  LLS{bruteforce_with_a_hamm                                                                                                                    
abcde                                                                                                                                                 
FLAG =  LLS{bruteforce_with_a_hamme                                                                                                                   
abcdefghijklmnopqr                                                                                                                                    
FLAG =  LLS{bruteforce_with_a_hammer                                                                                                                  
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&'()*+,-./:;<=>?@[\]^_`{|}                                                         
FINAL FLAG =  LLS{bruteforce_with_a_hammer}                                                                                                           
[*] Closed connection to jh2i.com port 50012
```

### 6. CALC-UL8R

#### Description [150]
Texas Instruments latest new product: you!

Connect with:

`nc jh2i.com 50003`

Solution:- As the challenge name was calculator so I had to enter the answer. But each time I enter the answer question changes randomly so I used the selelnium with a website [mathhapa.com](https://www.mathpapa.com/). To solve this I wrote a simple python script.

```
from __future__ import print_function
from pwn import *
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options  
import urllib

url = "https://www.mathpapa.com/algebra-calculator.html?q="
chrome_options = Options()  
chrome_options.add_argument("--headless")  
driver = webdriver.Chrome("/home/gr4n173/ctfscripting/chromedriver")
#nc jh2i.com 50003
r = remote('jh2i.com', 50003)
r.recvline()
r.recvline()
r.recvline()
r.recvline()
r.recvline()
r.recvline()
r.recvline()
while True:
    soal = r.recvline()
    print(soal)
    resp = r.recvuntil("= ")
    driver.get(url + urllib.quote(soal.replace("e","x")));
    driver.implicitly_wait(30)
    elements = driver.find_elements_by_css_selector("div#solout3 div.vspacediv fmath mn")
    text = 0
    i=0
    for element in elements:
        if(text==0):
            text = float(element.text)
        else:
            text /= float(element.text)
    if(text.is_integer()):
        text = str(int(text))
    else:
        text = str(float(text))
    r.send(text)
    print("ANSWER",text)
    print(r.recvline())
    

driver.close()   
```

At last this script lend me the flag:-

```
LLS{sympy_to_solve_equations}
```

This way I solved 6 challenges from scripting. Follow my blog to see more writeup of other catageory and I was able to solve more challenge from `Web` Challenges which writeup is comming soon. Stay tuned.

#Stay_safe

#COVID-19

