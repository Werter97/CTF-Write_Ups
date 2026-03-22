# Breadcrumbs (Misc / Crypto)

**Points:** 100
**Category:** Misc 

## Description
"Every trail has a beginning. This one starts here: `https://gist.github.com/garvk07/3f9c505068c011e0fd6abd9ddf56aecb`
Follow the breadcrumbs. The flag is at the end."

##Approach
This challenge was a scavenger hunt requiring many decoding techniques. I followed the trail of Gist links.
### Breadcrumb 1: Base64
Navigating to the initial Gist URL, I found the following string:
`aHR0cHM6Ly9naXN0LmdpdGh1Yi5jb20vZ2FydmswNy9iYTQwNjQ2MGYyZTkzMmI1NDk2Y2EyNTk3N2JlMjViZQ==`

The `==` padding at the end is a showed it was Base64 encoding. I decoded this using CyberChef, which revealed the next link:
`https://gist.github.com/garvk07/ba406460f2e932b5496ca25977be25be`

### Breadcrumb 2: Plaintext Link
Visiting the second Gist provided a direct plaintext link to the third step on the trail:
`https://gist.github.com/garvk07/963e70be662ea81e96e4e63553038d1a`

### Breadcrumb 3: Hexadecimal to Text
The third Gist contained a small Python script with a comment block.After trying 2-3 things of the commented string `68747470733a2f2f676973742e6769746875622e636f6d2f676172766b30372f3564356566383539663533306333643539336134613363373538306432663239`, I found that simply converting it to hex string then to bytes and then to chars, i get a gist url.

### Breadcrumb 4: The Final Gist
Navigating to the URL recovered from the hexadecimal string (`https://gist.github.com/garvk07/5d5ef859f530c3d593a4a3c7580d2f29`), I finally reached the end of the trail. Instead of another link, this Gist contained a string looking like flag:
`hgsynt{s0yy0j1at_gu3_pe4jy_ge41y}`

### Breadcrumb 5: The ROT13 Cipher
The string `hgsynt{...}` looked standard flag format for this CTF,`utflag{...}`. 

By analyzing the difference between the first letters, I noticed that `h` is exactly 13 letters away from `u` in the English alphabet, `g` is 13 away from `t`, and `s` is 13 away from `f`. This indicated that the text was encrypted by a **ROT13** cipher.
So i wrote a python code and decoded it to get the flag.

## Flag
`utflag{f0ll0w1ng_th3_cr4wl_tr41l}`

## Exploit
```python
#Breadcrumb 3:
enc=bytes.fromhex("68747470733a2f2f676973742e6769746875622e636f6d2f676172766b30372f3564356566383539663533306333643539336134613363373538306432663239")
leak=""
for b in enc:
    leak+=chr(b)
print(leak)
#
#Breadcrumb 4:
#hgsynt{s0yy0j1at_gu3_pe4jy_ge41y}
x="hgsynt{s0yy0j1at_gu3_pe4jy_ge41y}"
a=""
for ch in x:
    if 'a'<=ch<='z':
        if(ord(ch)-ord('a')<13) :
            a+=(chr(ord(ch)+13))
        else:
            a+=(chr(ord(ch)-13))
    else:
        a+=ch
print(a)
#utflag{f0ll0w1ng_th3_cr4wl_tr41l}