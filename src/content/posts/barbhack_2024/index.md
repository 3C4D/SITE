---
title: Write-up CTF Barbhack 2024
published: 2024-09-03
description: CTF Barbhack 2024 - Write-up des épreuves de Reverse
tags: [write-up, ctf, reverse]
image: /images/barbhack_2024/barbhack.jpg
category: Write-Ups
draft: false
---

# Barbhack 2024

**Barbhack** est une conférence basée sur la sécurité informatique se déroulant dans
le sud de la France. Le principe est simple : **BBQ + Hack**

La conférence dure une journée et se cloture le lendemain matin après un CTF auquel
mon équipe et moi-même avons pu finir 3eme.

Je vais détailler dans cet article la catégorie sur laquelle je me suis le plus concentré à
savoir les épreuves de **reverse engineering**.

:::note
Mention spéciale à l'orga de la conférence qui a assuré ce jour la pour que tout
tienne la route. Aussi, une serie d'épreuves basée sur Active Directory était réalisable
durant le CTF, ce que je n'avais alors jamais vu.
:::

# Reverse Engineering

Sommaire :
- [REV01: simplest](#rev01-simplest)
- [REV02: don't format me](#rev02-dont-format-me)
- [REV03: simple_math](#rev03-simple_math)

## REV01: simplest
À première vue, le binaire peut paraître simple. On peut directement voir avec
l'outil `strings` qu'il contient une chaîne de caractère codée en dur ayant un format de
flag :
```
+--> strings -n20 simplest
/lib64/ld-linux-x86-64.so.2
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
Usage: %s <password>
Usage: %s <correct_password...>
Well done you can validate this flag !

brb{th1s_i5_th3_fl4g}                               <----------

GCC: (Gentoo 13.2.1_p20240210 p14) 13.2.1 20240210
GCC: (Gentoo 13.3.1_p20240614 p17) 13.3.1 20240614
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
_ITM_deregisterTMCloneTable
__stack_chk_fail@GLIBC_2.4
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
```

Cela ne semble pas être le bon flag lorsqu'on le passe en argument du programme...

En décompilant le binaire avec l'outil `ghidra`, nous pouvons voir plusieurs choses,
notamment une reconsitution en pseudo-code de la fonction `main`.

La maison ne reculant devant aucun sacrifice, j'ai **retypé les fonctions et les variables**
afin de rendre la fonction plus lisible :
```c
int main(int argc,char *argv){
  int ret; int len;
  
  if (argc < 2) {
    fprintf(stderr,"Usage: %s <password>\n", argv[0]);
    ret = 1;
  }
  else {
    len = strlen(argv[1]);
    ret = are_equals(argv[1],0x104020,len);
    if (ret) {
      puts("Well done you can validate this flag !");
      ret = 0;
    }
    else {
      fprintf(stderr,"Usage: %s <correct_password...>\n", argv[0]);
      ret = 1;
    }
  }
  return uVar1;
}
```

On peut observer que le flag que nous donnons au paramètre du programme est comparée à la chaîne
se trouvant à l'offset 0x104020 du programme. Après analyse, cette chaîne se révèle bien être
`brb{th1s_i5_th3_fl4g}`. Cependant, ce n'est pas le flag selon la sortie du programme.

### Changement dynamique de flag
En se servant de `gdb`, nous pouvons mettre un breakpoint sur l'appel à la fonction `are_equals`
et imprimer le flag juste avant la comparaison :
```
(gdb) p &FLAG
(gdb) x/s 0x555555558020
0x555555558020 <FLAG>:	"brb{th1s_i5_th3_fl4g}"
(gdb) b are_equals
Breakpoint 1 at 0x5555555552f6
(gdb) r test
[...]
Breakpoint 1, 0x00005555555552f6 in are_equals ()
(gdb) x/s 0x555555558020
0x555555558020 <FLAG>:	"Arb{0_no_Ive_b33N_f0und___W3LL_d0NE_newb}"
```

Le flag a **changé** durant l'exécution alors que rien ne semblait l'indiquer dans la fonction `main` !
Nous avons maintenant le bon flag, reste à savoir comment il est arrivé la :/

### Subtilité dans l'Entry Point
J'ai remarqué après avoir trouvé le flag qu'une fonction du programme ne m'avait pas interperlé
à la première analyse, la fonction `dontmindme` :
![image](/images/barbhack_2024/dontmindme.png)

Cette fonction semble être appelée avant la fonction `main`, on peut s'en assurer en mettant un
breakpoint sur les deux fonction et en lancant le programme dans gdb.

On peut voir en analysant la fonction que c'est bien elle qui est responsable du changement de
la variable globale `FLAG`.

Une version lisible de `dontmindme` :
```c
void dontmindme(void){
  int i;
  
  offsets = {
    52, 30, 47, 55, 114, 30, 13, 113, 47, 113, 15, 35,
    30, 113, 46, 54, 8, 30, 36, 60, 37, 39, 47, 4, 30,
    51, 58, 35, 117, 22, 36, 13, 30, 114, 35, 30, 30, 30,
    37, 15, 35};

  keys = {20, 30, 6, 10, 14, 35, 28, 32, 36, 19, 33, 2, 5,
    4, 7, 38, 9, 8, 11, 40, 22, 18, 21, 34, 12, 12, 3, 13, 15,
    26, 37, 29, 23, 27, 39, 24, 17, 25, 31, 16
  };
  
  for (i = 0; i < 42; i = i + 1) {
    FLAG[offsets[i]] = keys[i] ^ 0x41;
  }
  return;
}
```

Après simulation, le flag est bien : `brb{0_no_Ive_b33N_f0und___W3LL_d0NE_newb}`


## REV02: Don't Format Me

L'épreuve nous donne un fichier sensé être un plugin utilisable dans Visual Studio Code.
Selon la commande `file`, le fichier `formatme-0.0.1.vsix` est une archive zippée :
```
+--> file formatme-0.0.1.vsix
formatme-0.0.1.vsix: Zip archive data, [...]
```

:::warning
La commande `file` n'est pas fiable à 100%, elle se base aux magic bytes et
aux éventuelles metadonnées
:::

Dézipper le plugin fonctionne et nous donne quelques dossiers/fichiers.
Le plus intéressant d'entres-eux est : `extension/dist/extension.js` :

```javascript
(()=>{"use strict";var e={265:function(e,t,r){var a=this&&this.__createBinding||(Object.create?
function(e,t,r,a){void 0===a&&(a=r);var o=Object.getOwnPropertyDescriptor(t,r);o&&!("get"in o?!
t.__esModule:o.writable||o.configurable)||(o={enumerable:!0,get:function(){return t[r]}}),Object
.defineProperty(e,a,o)}:function(e,t,r,a){void 0===a&&(a=r),e[a]=t[r]}),o=this&&this.__setModule
Default||(Object.create?function(e,t){Object.defineProperty(e,"default",{enumerable:!0,value:t})}
:function(e,t){e.default=t}),f=this&&this.__importStar||function(e){if
(e&&e.__esModule)return e;var t={};if(null!=e)for(var r in e)"default"!==r&&Object.prototype.has
OwnProperty.call(e,r)&&a(t,e,r);return o(t,e),t};Object.defineProperty(t,"__esModule",{value:!0})
,t.activate=function(e){Buffer.from("36756fe62567ea3dd22be697534eaa63f86d48d9e67f66c9d9ed600f2286
054c","hex"),c.languages.registerDocumentFormattingEditProvider("python",{provideDocumentFormattingEdit
s(e){const t=c.window.activeTextEditor;if(!t)return[];let r=t.document.getText().replaceAll("r","w");
r=r.replaceAll("R","W"),Buffer.from("ec9cc19bff42faa3be6e33e099b17f734a1c2af7abdd2955bbd59d72ddbdb17
a","hex"),Buffer.from("e38d0d4a1e3b5f2ae3cfb618698ad736a10789539cf5bcec368ef13e134c2c3a","hex"),new
Map([["import","impowt"],["break","bweak"],["raise","waise"],["True","Twue"],["return","wetuwn"],[
"for","fow"],["try","twy"],["from","fwom"],["assert","assewt"],["or","ow"]]).forEach(((e,t)=>{r=r.
replaceAll(e,t)}));let a=new c.Range(0,0,t.document.lineCount,0),o=t.document.validateRange(a),f=
Buffer.from("076a89c23179cedfc61171fe400ecf01fb76b9a48a68fb82dd0cd688d684d900","hex"),n=Buffer.
from("d4c1567970bf9e4f541abfeb4c9314c6bcb5374d81dd612bae0dbece6d46b282","hex");return 0!==Buffer
.compare(i,f)&&0!==Buffer.compare(i,n)&&t.edit((e=>{e.replace(o,r)})),[]}})},t.deactivate=functi
on(){};const c=f(r(398)),n=r(857),{createHash:d}=r(982);let i=d("sha256").update((u=(0,n.userInf
o)().username,s=(0,n.hostname)(),`${u}@${s}`).toLowerCase()).digest();var u,s},398:e=>{e.exports=
require("vscode")},982:e=>{e.exports=require("crypto")},857:e=>{e.exports=require("os")}},t={},r=
function r(a){var o=t[a];if(void 0!==o)return o.exports;var f=t[a]={exports:{}};return e[a].call(
  f.exports,f,f.exports,r),f.exports}(265);module.exports=r})();
```

Je suis d'accord, le code n'est pas très accueillant. C'est un code Javascript décrivant le comportement
de l'extension.

Notre mission dans cette épreuve est de retrouver **le nom d'utilisateur et le hostname** utilisés dans
cette extension (sous la forme `utilisateur@hostname`). Certaines lignes attirent donc notre attention :
```javascript
 let i = d("sha256").update((u = (0, n.userInfo)().username, s = (0, n.hostname)(), `${u}@${s}`).toLowerCase()).digest();
```

On peut voir que le format `${u}@${s}` correspond au format `utilisateur@hostname`. Il faut maintenant
trouver quelles sont les valeurs de `u` et de `s`.

### Trouvez les hashs
La fonction de hachage sha256 est utilisée à plusieurs endroits du code, notamment celui-ci :
```javascript
let a = new c.Range(0, 0, t.document.lineCount, 0),
    o = t.document.validateRange(a),
    f = Buffer.from("076a89c23179cedfc61171fe400ecf01fb76b9a48a68fb82dd0cd688d684d900", "hex"),
    n = Buffer.from("d4c1567970bf9e4f541abfeb4c9314c6bcb5374d81dd612bae0dbece6d46b282", "hex");

return 0 !== Buffer.compare(i, f) && 0 !== Buffer.compare(i, n) && t.edit((e => {
    e.replace(o, r)
})), []
```

En faisant des recherches (http://crackstation.net), les hash correspondent aux mots `fernando`
et `lovemachine`. Aussi, on peut savoir que la variable `i` est le résultat du sha256 de
`username@hostname`.

Le sha256 de "fernando@lovemachine" est `ec9cc19bff42faa3be6e33e099b17f734a1c2af7abdd2955bbd59d72ddbdb17a`, ce
qui correspond à un hash trouvé plus haut :
```javascript
r = r.replaceAll("R", "W"),
    Buffer.from("ec9cc19bff42faa3be6e33e099b17f734a1c2af7abdd2955bbd59d72ddbdb17a", "hex"),  <---------
    Buffer.from("e38d0d4a1e3b5f2ae3cfb618698ad736a10789539cf5bcec368ef13e134c2c3a", "hex"),
    new Map([
    ["import", "impowt"],
    ["break", "bweak"],
    ["raise", "waise"],
    ["True", "Twue"],
    ["return", "wetuwn"],
    ["for", "fow"],
    ["try", "twy"],
    ["from", "fwom"],
    ["assert", "assewt"],
    ["or", "ow"]
]).forEach(((e, t) => {
    r = r.replaceAll(e, t)
}));
```

Le flag est bien : `brb{fernando@lovemachine}`

## REV03: simple_math
l'exécutable `simple_math` nous demande un mot de passe et ne donne aucune sortie :
```
+--> ./simple_math
Enter password
testpassword

```

Nous pouvons décompiler le programme avec `ghidra` :
![image](/images/barbhack_2024/ghidra2.png)

Pas de fonction `main` à l'horizon, rien à part une suite interminable de tests booléens.
On se rend vite compte que la variable `DAT_0804e010` est le début de la chaîne que l'on a
fourni au programme. Ainsi, `DAT_0804e011` sera le second caractère, `DAT_0804e012` le troisième
et ainsi de suite. Le flag serait en théorie une chaîne de caractère validant tous les tests.

### Equations linéaires
Il est facile de résoudre une addition : `x - 10 = 0` implique `x = 10`. Lorsqu'il est question
de 32 variables inconnues dans un système d'équations linéaires, c'est un autre sport.

Heureusement, nous possédons autant d'inconnues (le flag contient 32 caractères
selon les variables testées) que d'équations. Selon la règle de [Cramer](https://fr.wikipedia.org/wiki/R%C3%A8gle_de_Cramer),
un système d'équations
linéaires avec autant d'équations que d'inconnues et dont le déterminant de la matrice de
coefficient est non nul **admet une unique solution**. Nous passerons sur le calcul du déterminant car
nous sommes sur qu'il existe un flag.

### Résolution du système
En copiant le pseudo-code fourni par `ghidra` et en le modifiant, on arrive à extraire les 32 équations.
J'ai pu écrire un programme en python qui résout le système à l'aide de la librairie `sympy`.
```python
from sympy.solvers import solve
from sympy import var,Eq

print("[+] L'ordinateur résout le système...")
var('a b c d e f g h i j k l m n o p q r s t u v w x y z a1 a2 a3 a4 a5 a6')

eq1=Eq(((((((a*-4+b*-5+c*2+d*-5+e*7+f*-7+g*3+h*-5+i*-3+j*-3+l*-5+m+n*5+o*5+p*-4)-q)-r)-s)+t*-2+u*3)-v)+w*-5+x*-7+y*2+z*2+a1*-6+a2*-4+a3*-4+a4*-3+a5*-2+a6*4,-0x13e9)
eq2=Eq(((a*4+b*2+c*-4+d*2+e+f*-2+g*-3+h*4+i*-7+j*3+l*3+m*6+n*-4+o*5+p*6+q*-6+r*6+s+t*3+u*2+v*-4+w*-7+x*6)-y)+z*5+a1*-5+a2*7+a3*7+a4*4+a5*5+a6*-2,0x1025)
eq3=Eq((((((((b*3-a)+c*-6+d*4+e+f*-5+g*3)-h)+i*5+j*4+l*4+m*3)-n)+o*2+p*-4+q*4+r*-2+s+t*-5+u*6+v*-7+w+x*7+y*-7+z*-7+a1+a2*-2)-a3)+a4*-5+a5*5+a6*-4,0x17b)
eq4=Eq((a*-5+b*3+c*5+d+e*4+f*-6+g*-5+h*5+i*-7+j*6+l*-7+m*-7+n*-6+o*6+p*3+q*4+r*-4+s*5+t*3+u*2+v+w*-4+x*4+y*-5+z*-5+a1*-4+a2*5+a3*2+a4*2+a5*-6)-a6,-0x377)
eq5=Eq(a*2+b*-2+c*2+d*-2+e*6+f*6+g*3+h*3+i*-3+j*-6+l*2+m*-7+n*2+o*6+p*-5+q*7+r*3+s*7+t*-7+u*7+v*6+w*-5+x*6+y+z*4+a1*5+a2*-4+a3*5+a4*5+a5*-2+a6*-2,0x1497)
eq6=Eq((((((((a+b*3+c*7+d*-2+e*-2+f*-3+g*6)-h)-i)+j*-7+l*-2+m*-4+n*-6)-o)+p*-5+q*7+r+s*7+t*5+u*3+v*-4)-w)+x*-3+y*-7+z*5+a1*2+a2+a3*7+a4*7+a5*6+(a6*8-a6),0x7c2)
eq7=Eq(((((((b*-3-a)+c*3+d*7+e*6+f*-4+g*-6)-h)+i*-3+j*2+l*-6+m*6)-n)+o*-4+p*-6+q+r*-3+s+t*5+u*4+v*-4+w*-4+x*-3+y*-3+z*-3+a1*-6+a2*-3+a3*7+a4*-5+a5*-6)-a6,-0xedc)
eq8=Eq(a*-4+b*4+c*-6+d*-7+e+f*7+g+h*-4+i*-4+j*3+l*-5+m*7+n*5+o*4+p*-4+q*7+r*-5+s*5+t*-2+u*2+v*5+w*-4+x*-5+y+z*-4+a1*-2+a2*5+a3*6+a4*5+a5*4+a6*4,0x851)
eq9=Eq(((((a*6+b*6+c*-7+d*-3+e*-4)-f)+g*6+h*-6+i*-6+j*7+l*-3+m*-4+n*2+o*-2+p*-2+q*4+q+r*-6+s*3+t*-5+u*-3+v*-3+w*-3+x*2+y*3+z*3)-a1)+a2*3+a3*6+a4*7+a5*2+a6*6,0x2dd)
eq10=Eq(((((a*-7+b+c*5)-d)+e*7+f+g*7+h*-3+i*6+j*7+l*3+m*-3+n*-6+o*4+p*3+q*2+r*3)-s)+t*4+u*-7+v*-7+w*4+x*-4+y*-2+z*6+a1*-3+a2*2+a3+a4*7+a5*5+(a6*8-a6),0xdd7)
eq11=Eq(((a*7+b*6+c*7+d*-5+e*-7+f*7+g*6+h*2+i*3+j*-2+l*3+m*-7+n*2+o*-4+p+q+r*-3+s*-6)-t)+u*-7+v*-6+w*-2+x*7+y*2+z*2+a1*-5+a2*7+a3*-3+a4*7+a5*2+a6*6,0x61b)
eq12=Eq((((((((((a*-3+b*-6+c*6+d*5+e*2+f+g*2+h*7+i*-5+j*4)-l)+m*5+n*-6+o*6+p*-4+q*-7+r*4+s*3)-t)+u*2+v*-4+w*6)-x)+y*7+z*-7+a1*3+a2*-3+a3*7)-a4)-a5)+a6*-2,0x6ed)
eq13=Eq(((a+b*4+c*5+d*-3+e*-3+f*6+g*6+h*6+i*5+j*-5+l*7+m*-5)-n)+o*5+p*5+q*2+r*7+s*-5+t*2+u*-2+v*-5+w*-5+x*-3+y*6+z*-5+a1*-6+a2*-6+a3*2+a4*2+a5*-4+a6*6,0x3fc)
eq14=Eq(((((((a+b*-5+c*6+d*-6+e*7+f*-3+g*-3+h*-4+i*2+j*-2+l*5+m*-4)-n)+o*5+p*7+q*-5)-r)+s*-7+t*-5+u*6)-v)+w+x*2+y*-2+z*-6+a1*-2+a2*3+a3*-3+a4*2+a5*2+a6*4+a6,-0x377)
eq15=Eq((((a*5+b*-3+c*2+d*-3+e*5+f*-3+g*-4+h*-2+i*-3+j*-2+l*6+m*-5+n*2+o*-5+p*7+q*6+r*4+s*-5+t*-3+u*-5+v*5+w+x*5+y*6+z*-4+a1*-7+a2*-5)-a3)+a4*7+a5*2)-a6,700)
eq16=Eq(((((((((((a*-5+b*3)-c)+d*-5+e*-2+f*2+g*-7+h*-5+i*7)-j)+l*3+m*5+n*2+o*-6+p*7+q*6+r*5)-s)+t*-4)-u)+v*6+w*-7+x*-7+y*-3+z*-3+a1*-3+a2*-2+a3+a4*-3)-a5)+a6*4,-0x70f)
eq17=Eq((((((((((a*-2+b)-c)+d*7)-e)+f*-6+g*2)-h)+i*-2+j*-3+l*4+m*-6+n*6+o*-3+p*4+q*4)-r)+s*2+t*2+u*-7+v*7+w*-7+x*-3+y*7+z*7+a1*4+a2*-3+a3*6+a4*3+a5*3)-a6,0xaba)
eq18=Eq((((((((((((a*6-b)+c*-6+d*-7)-e)+f*7+g*6+(h*8-h))-i)+j*-4+l*-5+m*3+n*7+o*-3)-p)+q*-5+r+s*-2+t*-3)-u)+v*-5)-w)+x*7+y*4+y+z*-2+a1+a2*-4+a3*-3+a4*4+a5*-6+a6*4+a6,-0x3d8)
eq19=Eq((((((((((((a*6-b)+c*-6+d*-7)-e)+f*7+g*6+(h*8-h))-i)+j*-4+l*-5+m*3+n*7+o*-3)-p)+q*-5+r+s*-2+t*-3)-u)+v*-5)-w)+x*7+y*4+y+z*-2+a1+a2*-4+a3*-3+a4*4+a5*-6+a6*4+a6,-0x3d8)
eq20=Eq(((((a*-7+b*-2+c*-7+d*-3+e*-7+f*6+g*-4+h*2+i*-4+j*2+l*3+m*-4+n*3)-o)+(p*8-p)+q*-2+r*2+s*4+t*6+u*3+v*-2)-w)+x+y*-3+z*-6+a1*-2+a2*-7+a3*-4+a4*-4+a5*-5+a6*2,-0xfff)
eq21=Eq(a*6+b*-5+c*6+d*-6+e*-6+f*4+g*-7+h*6+i*-5+j*7+l*2+m*4+n*-3+o*-3+p*-4+q*-5+r*-6+s*6+t*-6+u*-6+v*4+w+x*-5+y*-5+z*-2+a1*5+a2*6+a3*6+a4*3+a5*-7+a6*-3,-0x5bc)
eq22=Eq(((((a*-6+b*-6+c*-4+d*5+e*6+f*-4+g*6+h*-4+i*-4)-j)+l*-3+m*4+n+o*-6+p*-5+q*5+r*3+s*-2+t*2+u*6+v*6+w*7+x*6+y*-6+z*-7+a1*5+a2*-6+a3*-5+a4*-5)-a5)+a6*4+a6,-0x593)
eq23=Eq(((((a*-6+b*-3+c*7+d*4+e*-4+f+g*-3+h*-3+i*-4+j*4+l)-m)+n*7+o*4+p*-2+q*6+r*7+s*4+t*-7+u*-6)-v)+w*-2+x*-5+y*5+z*-2+a1*3+a2*4+a3*-4+a4*-4+a5*-4+a6*-4,-0x48)
eq24=Eq(a*5+b*-3+c*-2+d*-4+e+f*6+g*-4+h*2+i*5+j*-2+l*6+m*-3+n*5+o*2+p*-3+q*-2+r*3+s*-4+t*7+u*-2+v*6+w*-6+x*5+y*4+z*3+a1+a2*6+a3*-3+a4*3+a5*3+a6*4+a6,0xd1f)
eq25=Eq(((a*4+b*-4+c*-2+d*3+e*-3+f*2+g+h*3)-i)+j*2+l*3+m*6+n*-5+o*4+p*2+q*7+r*-5+s*-3+t*2+u*7+v*5+w*6+x*-4+y*-3+z*-6+a1*3+a2*4+a3*5+a4*3+a5*5+a6*-6,0x1148)
eq26=Eq((((((((((a*-3+b)-c)+d*-3+e*-6+f*-4+g*4+h*-5+i*-2+j*-4+l*7+m*-3+n*-4+o*3+p*-6+q*3+r*-5+s*-2)-t)+u*5)-v)+w*3+x*4+y*-2)-z)-a1)+a2*-5+a3*-3+a4*-4+a5*-5+a6*-7,-0x11d7)
eq27=Eq(((((a*-5+b*5+c*7+d*-2+e*-2+f*4+g*-6)-h)+i*-6+j*-3+l*-5+m*-4+n*-4+o*-5+p*-6+q*2+r*5)-s)+t*-4+u*-4+v*-5+w*-7+x*5+y*-5+z*6+a1*5+a2*5+a3*5+a4*-2+a5*-2+a6*4+a6,-0xbba)
eq28=Eq((((a*5+b*-3+c*-2+d*7+e*3+f*7)-g)+h*-3+i*-6+j*7+l*4+m*7+n*3+o*-3+p*-5+q*-6+r*2+s*-2+t*2+u*6+v*2+w+x*5+y*-5+z*4+a1*2+a2*-5+a3*4+a4*6+a5*-5)-a6,0xc0c)
eq29=Eq((((a*2-b)+c*-2+d*-6)-e)+f*3+g*-5+h*-7+i+j*-6+l*-3+m*-2+n*-6+o*-4+p*3+q*5+r*6+s+t*-5+u*3+v*3+w*-4+x*3+y*-7+z+a1*7+a2*3+a3*-5+a4*-7+a5*7+a6*-7,-0x8d7)
eq30=Eq(((((((b*5-a)+c*-5+d*-5+e*4+f*3+g*-7+h*7+i*6+j*3+l*-6+m*-6)-n)+o*2+p*-3+q*-6+r*3+s*-2+t*-2+u*6)-v)-w)+x*-2+y*3+z+a1*-7+a2*7+a3*6+a4*-6+a5*-6+a6*2,-0x48b)
eq31=Eq(((a*-6+b*-5+c*7+d*-4+e*-7+f+g*4+h*2+i*-2+j*5+l*-2+m*3+n*3+o*-5+p*4+q+r*2+s*-7)-t)+u*2+v*5+w*6+x*2+y*2+z*3+a1*-3+a2*5+a3*2+a4*-4+a5*3+a6,0x683)
eq32=Eq((((((((a*7+b*2+c*5+d*2+e*7+f*6)-g)-h)+i*7+j*-3+l*-4+m*6)-n)+o*4+p*-6+q*-6+r*2+s*-4+t*5+u*-3+v*-5)-w)+x*-3+y*-2+z*-5+a1*-6+a2*-5+a3*3+a4*3+a5*-4+a6*6,-0x31a)

output=solve([eq1,eq2,eq3,eq4,eq5,eq6,eq7,eq8,eq9,eq10,eq11,eq12,eq13,eq14,eq15,eq16,eq17,eq18,eq19,eq20,eq21,eq22,eq23,eq24,eq25,eq26,eq27,eq28,eq29,eq30,eq31,eq32],
             a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,a1,a2,a3,a4,a5,a6,
             dict=True
)
# Mais ou est passé le k ?
flag = ''.join([chr(output[0][i]) for i in [a,b,c,d,e,f,g,h,i,j,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,a1,a2,a3,a4,a5,a6]])
print("[+] ...Done, Le flag est :", flag)
```

```
[+] L'ordinateur résout le système...
[+] ...Done, Le flag est : brb{that_is_very_s1mple_maths}
```

Le flag est donc : `brb{that_is_very_s1mple_maths}`
