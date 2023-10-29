---
title: "Write-up DEADFACE CTF 2023"
description: "Write-up DEADFACE CTF 2023"
pubDate: "Oct 23 2023"
heroImage: "/deadface.jpg"
setup : |
  import { Image } from 'astro:assets'
---

# DEADFACE 2023

La DEADFACE édition 2023 nous est proposée par l'équipe Cyber hacktics
et nous expose tout au long de la compétition un fil conducteur ce qui
est plutôt rare et très appréciable en CTF.

Mon équipe et moi-même (Les Garagistes) avons fini 72eme.

Je vais vous proposer une correction de quelques épreuves que j'ai pu
faire dans diverses catégories. N'hésitez pas à me contacter par mail
ou mp Root-me pour de plus amples questions.

Vous pouvez aussi rendre visite au site d'un de mes coéquipiers pour
avoir accès à la correction d'autres épreuves de la compétitions :
[**jeanchaput.fr**](https://jeanchaput.fr/).

# Reverse Engineering

## Cereal Killer 1

En décompilant l'exécutable avec `Ghidra`, nous pouvons voir la fonction
`main` :

```c
undefined4 main(undefined param_1)
{
  int iVar1;
  undefined4 uVar2;
  int in_GS_OFFSET;
  char *local_1090;
  char *local_108c;
  char *local_1088;
  char local_1078 [100];
  char local_1014 [4096];
  int local_14;
  undefined1 *local_10;
  
  local_10 = &param_1;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  local_108c = "I&_9a%mx_tRmE4D3DmYw_9fbo6rd_aFcRbE,D.D>Y[!]!\'!q";
  puts("Bumpyhassan loves Halloween, so naturally, he LOVES SPOOKY CEREALS!");
  puts("He also happens to be a fan of horror movies from the 1970\'s to the 1990\'s.");
  printf("What is bumpyhassan\'s favorite breakfast cereal? ");
  fgets(local_1014,0xfff,_stdin);
  for (local_1090 = local_1014; *local_1090 != '\0'; local_1090 = local_1090 + 1) {
    *local_1090 = *local_1090 + '\a';
  }
  *local_1090 = '\0';
  iVar1 = memcmp(&DAT_00012039,local_1014,0xe);
  if (iVar1 == 0) {
    puts("You are correct!");
    local_1088 = local_1078;
    for (; *local_108c != '\0'; local_108c = local_108c + 2) {
      *local_1088 = *local_108c;
      local_1088 = local_1088 + 1;
    }
    *local_1088 = '\0';
    printf("flag{%s}\n",local_1078);
  }
  else {
    puts("Sorry, that is not bumpyhassan\'s favorite cereal. :( ");
  }
  uVar2 = 0;
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
    uVar2 = __stack_chk_fail_local();
  }
  return uVar2;
}
```

On pourrait résoudre l'épreuve de deux façons :

### Première méthode :

On identifie le test qui permet d'afficher le flag :

```c
iVar1 = memcmp(&DAT_00012039,local_1014,0xe);
  if (iVar1 == 0) {
    puts("You are correct!");

```

`DAT_00012039` est égal à : `My|p{\x80GRY\LNLY`

`local_1014` est la variable où est placé l'entrée du programme
lorsqu'on l'exécute et qu'il appelle `scanf` :

```c
fgets(local_1014,0xfff,_stdin)
```

Un traîtement est fait sur l'entrée `local_1014` avant de le
comparer :

```c
  for (local_1090 = local_1014; *local_1090 != '\0'; local_1090 = local_1090 + 1) {
    *local_1090 = *local_1090 + '\a';
  }
```

Dans ce code, on voit que `\a` est ajouté à chaque caractère de `local_1014`
pour obtenir la bonne chaîne à comparer, il suffit d'enlever `\a`, c'est à
dire `0x7` à chaque caractères pour obtenir le bon input. Petit programme :

```python
print("".join([chr(i-0x7) for i in bytes.fromhex("4d797c707b804752595c4c4e4c59")]))
# Fruity@KRUEGER
```

On le rentre dans le programme et on obtient le flag : `flag{I_am_REDDY_for_FREDDY!!!}`

### Seconde méthode :

On identifie la chaîne dans le programme qui lui permet de construire le flag ainsi que
le bout de code qui le construit :

```c
...
char *local_1088;
char local_1078 [100];
...
local_108c = "I&_9a%mx_tRmE4D3DmYw_9fbo6rd_aFcRbE,D.D>Y[!]!\'!q";
...
local_1088 = local_1078;
for (; *local_108c != '\0'; local_108c = local_108c + 2) {
    *local_1088 = *local_108c;
    local_1088 = local_1088 + 1;
}
*local_1088 = '\0';
printf("flag{%s}\n",local_1078);
...
```

On voit la boucle `for` met un caractère sur deux de la variable `local_108c`
en partant du premier dans la variable `local_1088 (== local_1078)`.

La chaîne sera donc `I_am_REDDY_for_FREDDY!!!` qu'il faudra mettre dans la chaîne
`flag{...}`

## Cereal Killer 2

En décompilant le programme avec `Ghidra`, dans la fonction `main`, on peut
voir la partie la plus importante du programme :

```c
  fgets(local_2014,0xfff,_stdin);
  decode_str((int)local_2014,0x3f,0x12094,(int)local_1014);
  iVar1 = strncmp(local_1014,"CORRECT!!!!!",0xc);
  if (iVar1 == 0) {
    puts(local_1014);
  }
```

L'entrée standard est placée dans la variable `local_2014`.
`decode_str` met visiblement quelque chose dans `local_1014`
qui va devoir être égal à `CORRECT!!!!!`.

La fonction en question :

```c
void decode_str(int param_1,int param_2,int param_3,int param_4)

{
  int local_10;
  int local_c;
  
  local_10 = 0;
  local_c = 0;
  while (local_c < param_2) {
    *(byte *)(param_4 + local_c) = *(byte *)(param_3 + local_c) ^ *(byte *)(param_1 + local_10);
    local_c = local_c + 1;
    local_10 = local_10 + 1;
    if (0xb < local_10) {
      local_10 = 0;
    }
  }
  *(undefined *)(param_4 + local_c) = 0;
  return;
}
```

Basiquement, la fonction met dans `param_4` le contenu de `param_1`
xoré avec la chaîne `param_3`.

La chaîne passée en troisième argument de `decode_str` peut se trouver
dans la variable `DAT_00012094`, nous pouvons donc construire un petit
programme pour retrouver le flag :

```python
A = "CORRECT!!!!!"
B = "\x08\x3d\x33\x3f\x15\x36\x32\x47\x52\x12\x1b\x65"
print("".join([chr(ord(A[i])^ord(B[i])) for i in range(len(A))]))
# KramPuffs3:D
```

On rentre `KramPuffs3:D` en input du programme, le flag s'affiche : `flag{GramPa-KRAMpus-Is-Comin-For-Da-Bad-Kids!!!}`

## Cereal Killer 4

L'épreuve se présente sous la forme d'un `.jar`, nous le décompilons avec
l'outil `jadx`.

Nous pouvons voir en ouvrant le jar le fichier décompilé `CenobBytes.java`.

Ce fichier dépend du dossier sheepy aussi fourni dans le jar.

Une solution assez simple est d'extraire le tout et de l'exécuter sans la
partie qui arrête le programme si l'input donnée est fausse.

On enlève donc les lignes suivantes :

```java
if (!amhoDecStr.equals(sayongchaAmho)) {
  System.out.println("Sorry, that is not the correct monster / cereal / password.  Please try again.");
  System.exit(0);
}
```

Le flag s'affiche sous forme d'ascii art, on voit : `flag{OctoberIsSharkMonth}`

## My Daily Macros

En dézippant l'archive fournie, on peut voir un document `Excel` : `HR_List.xlsm`.

En prenant en compte le nom de l'épreuve, on déduit que le thème sera les macros
contenus dans les documents `Office`.

On utilise `olevba` pour extraire les macros :

``` powershell
Sub Deadface()
function Invoke-RandomCode {
    $randomCodeList = @(
        {
            # Random code block 1
            Write-Host "Hello, World!"
            $randomNumber = Get-Random -Minimum 1 -Maximum 100
            Write-Host "Random number: $randomNumber"
        },
        {
            # Random code block 2
            # flag{youll_never_find_this_}
            $randomString = [char[]](65..90) | Get-Random -Count 5 | foreach { [char]$_ }
            Write-Host "Random string: $randomString"
        },
        {
            # Random code block 3
            $currentTime = Get-Date
            Write-Host "Current time: $currentTime"
        }
    )

    $randomIndex = Get-Random -Minimum 0 -Maximum $randomCodeList.Count
    $randomCodeBlock = $randomCodeList[$randomIndex]

    & $randomCodeBlock
}

Invoke -RandomCode

End Sub
```

Dans ce code `PowerShell`, nous pouvons voir le flag : `flag{youll_never_find_this_}`.

# Steganography

## Fetching secrets

Sur le forum fictif de la compétition, on peut trouver mention d'un programme nommé
`stegseek`. On l'installe et on l'utilise sur l'image de chien fournie dans l'épreuve.

`stegseek` permet de trouver automatiquement le chiffrement appliqué, on lui fourni
aussi une liste de mots afin qu'il puisse trouvé la clé de déchiffrement.

```
+--> stegseek --crack cyberdog.jpg -wl ~/Téléchargements/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "kira")

[i] Extracting to "cyberdog.jpg.out".
```

L'image `cyberdog.jpg.out` contient le flag : `flag{g00d_dawg_woofw00f}`.

## Electric Steel

En appliquant le programme `binwalk` sur l'image fournie dans l'épreuve, nous pouvons
voir une archive `gzip` contenu dans l'image :

```
+--> binwalk -D='.*' electric-steel.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1232 x 928, 8-bit/color RGB, non-interlaced
2767          0xACF           Zlib compressed data, default compression
1435378       0x15E6F2        TIFF image data, big-endian, offset of first image directory: 8
1435914       0x15E90A        Copyright string: "Copyright (c) 1998 Hewlett-Packard Company"
1467642       0x1664FA        gzip compressed data, from Unix, last modified: 2023-06-04 01:14:27
```

On la décompresse :

```
tar -xf 1664FA
```

On obtient le fichier `flag.txt` contenant le flag : `flag{3L3ctr1c_5t33L_b1G_H41R}`

# Cryptography

## Coin Code

L'image fournie dans l'épreuve indique un chiffrement césar de décalage 18, on l'applique
et on trouve :

```
Next target for me will be Aurora Pharma
```

flag : `flag{Aurora Pharma}`

## Color Me Impressed

Dans cette [page](https://ghosttown.deadface.io/t/chickens-cant-fly-but-these-ones-do-a-lot/128) du chat,
nous pouvons trouver une image avec 5 couleurs :

<Image
  src="/deadface_color.png"
  alt="labyrinthe"
  width="560"
  height="80"
/>

Si on concatène les codes hexa des couleurs (RGB), nous obtenons la suite
hexadécimale suivante :

```
476c403535482375243324744f6e33566d4035680a
```

On décode la suite :

```python
print(bytes.fromhex("476c403535482375243324744f6e33566d4035680a").decode())
# Gl@55H#u$3$tOn3Vm@5h\n
```

Le flag : `flag{Gl@55H#u$3$tOn3Vm@5h}`

# Bonus

## Off The Rails

On peut déduire à l'intitulé de l'épreuve que le message fourni est chiffré à l'aide
du chiffre Rail Fance.

On peut s'aider du site [dcode.fr](http://www.dcode.fr) afin de décoder automatiquement
le message, on obtient :

```
ITS NOT RUBY BUT IT IS ON THE RAILS HAVE A SPOOKY HALLOWEEN AND ENJOY
SOME SCARY MOVIES YOUR FLAG IS GHOST AND GHOULS
```

flag : `flag{GHOSTANDGHOULS}`