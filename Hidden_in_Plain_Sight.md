# Hidden in Plain Sight-25 (Misc)
**Points:** 100
**Category:** Misc
## Approach
An encrypted message was hidden in plain sight in the web url(which i noticed by looking at all components on the screen).

When i copied the url, i got the hidden text as:
`#Hidden%20%F3%A0%81%B5%F3%A0%81%B4%F3%A0%81%A6%F3%A0%81%AC%F3%A0%81%A1%F3%A0%81%A7%F3%A0%81%BB%F3%A0%80%B1%F3%A0%81%AE%F3%A0%81%B6%F3%A0%80%B1%F3%A0%81%B3%F3%A0%80%B1%F3%A0%81%A2%F3%A0%81%AC%F3%A0%80%B3%F3%A0%81%9F%F3%A0%81%B5%F3%A0%81%AE%F3%A0%80%B1%F3%A0%81%A3%F3%A0%80%B0%F3%A0%81%A4%F3%A0%80%B3%F3%A0%81%BDin%20Plain%20Sight-25`

The url is containing %20s followed by hexadecimal characters.So removing the spaces(%20 in url) we get the blocks of hexadecimals as:
`%F3%A0%81%B5%F3%A0%81%B4%F3%A0%81%A6%F3%A0%81%AC%F3%A0%81%A1%F3%A0%81%A7%F3%A0%81%BB%F3%A0%80%B1%F3%A0%81%AE%F3%A0%81%B6%F3%A0%80%B1%F3%A0%81%B3%F3%A0%80%B1%F3%A0%81%A2%F3%A0%81%AC%F3%A0%80%B3%F3%A0%81%9F%F3%A0%81%B5%F3%A0%81%AE%F3%A0%80%B1%F3%A0%81%A3%F3%A0%80%B0%F3%A0%81%A4%F3%A0%80%B3%F3%A0%81%BD`

### Decoding
I observed that in every 4-byte hex block, the first 3 bytes are almost the same (`%F3%A0%81`), and the 4th one changes.But in a few places, the 3rd byte is`%80`.

I tried to subtract a constant value from the 4th byte to see if we got the flag format `utflag{`. 
By comparing the target characters to the hex bytes, I found a constant difference:
* `0xB5` - `u` (0x75) = 0x40 (64)
* `0xB4` - `t` (0x74) = 0x40 (64)
* `0xA6` - `f` (0x66) = 0x40 (64)

I used this key of `64` to subtract from the encrypted string where 3rd hex was `0x81` and `63` where the third byte was `0x80`.

I got the flag: 
`utflag{rnvrsrblt_unrcqdt}`

I found the flag format but the inner string `rnvrsrblt_unrcqdt` was not meaningful

I observed the first word,`rnvrsrblt` to be similar to `invisible`.

If we assume the intended word is `invisible`,
* The `i`  was decoded as `r`.
* The `e` was decoded as `t`.

But `r-i`!=`t-e`,so I assumed instead of `i` let that be `1` as in many flags such things are formatted in such a way.
By subtracting `r`-`1`, i found the decoded characters to be`r` -> `1`, `t` -> `3`, `q` -> `0` 
When i replaced them with their values in flag, i got the flag word to be:
`1nv1s1bl3_un1c0d3`(This is meaningful (invisible unicode)).

## Flag
`utflag{1nv1s1bl3_un1c0d3}`

## Exploit
```python
#Hidden%20%F3%A0%81%B5%F3%A0%81%B4%F3%A0%81%A6%F3%A0%81%AC%F3%A0%81%A1%F3%A0%81%A7%F3%A0%81%BB%F3%A0%80%B1%F3%A0%81%AE%F3%A0%81%B6%F3%A0%80%B1%F3%A0%81%B3%F3%A0%80%B1%F3%A0%81%A2%F3%A0%81%AC%F3%A0%80%B3%F3%A0%81%9F%F3%A0%81%B5%F3%A0%81%AE%F3%A0%80%B1%F3%A0%81%A3%F3%A0%80%B0%F3%A0%81%A4%F3%A0%80%B3%F3%A0%81%BDin%20Plain%20Sight-25
enc="F3%A0%81%B5%F3%A0%81%B4%F3%A0%81%A6%F3%A0%81%AC%F3%A0%81%A1%F3%A0%81%A7%F3%A0%81%BB%F3%A0%80%B1%F3%A0%81%AE%F3%A0%81%B6%F3%A0%80%B1%F3%A0%81%B3%F3%A0%80%B1%F3%A0%81%A2%F3%A0%81%AC%F3%A0%80%B3%F3%A0%81%9F%F3%A0%81%B5%F3%A0%81%AE%F3%A0%80%B1%F3%A0%81%A3%F3%A0%80%B0%F3%A0%81%A4%F3%A0%80%B3%F3%A0%81%BD%"
leak=""
print(0xb5-117)
cnt=0
flag=0
while(cnt<(300)):
    if(cnt%12==7):
        flag=enc[cnt]
    if(cnt%12==9):
        s=enc[cnt]+enc[cnt+1]
        cnt+=1
        val=bytes.fromhex(s)
        if(flag=='1'):
            leak+=chr(val[0]-64)
        else:
            leak+=chr(val[0]-63)
    cnt+=1
print(leak)
