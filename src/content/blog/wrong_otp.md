---
title: "L'oubli de valeurs dans la mise en place d'un OTP"
description: "L'oubli de valeurs dans la mise en place d'un OTP"
pubDate: "Jul 07 2023"
heroImage: "/broken_face_mask.jpg"
---

# OTP

Dans les algorithmes de chiffrement par flot (ou chiffrement en
continu), nous utilisons des OTP, des **O**ne **T**ime
**P**ad, ou masques jetables (One time) en francais.

Dans la pratique, un OTP se présente sous la forme d'une suite
d'octets générée pour la plupart des cas à l'aide d'un
**générateur pseudo-aléatoire**.

La technique la plus courante est d'appliquer un **XOR** (ou
exclusif) entre l'OTP et le texte clair, le texte pouvant être
infini puisque l'OTP est, par définition du chiffrement par
flot, infini.

L'avantage de l'utilisation d'un OTP avec un générateur robuste
est que l'on a aucun moyen de deviner l'OTP utilié, en théorie.

Nous allons voir qu'en pratique, des erreurs mineures peuvent
mener à la compromission de ce système de chiffrement.

## Exemple de génération et d'utilisation d'un OTP

```python
 import random

 message = input()

 OTP = [random.randrange(0, 256) for i in range(len(message))]

 chiffre = "".join([chr(OTP[i] ^ ord(message[i])) for i in range(len(OTP))])
 dechiffre = "".join([chr(OTP[i] ^ ord(chiffre[i])) for i in range(len(OTP))])

 print("Message :", message)
 print("Message chiffré :", chiffre)
 print("Message déchiffré :", dechiffre)
```

Dans ce programme, nous pouvons voir que le message demandé sur
l'entrée standard va être chiffrée à l'aide d'une suite d'entiers
compris entre 0 et 255 bornes incluses, c'est à dire toutes les
valeurs possibles d'un octet.

L'opération OU exclusif étant reflexive, le déchiffrement consiste
à **chiffrer le chiffré** pour obtenir de nouveau le message
initial.

La robostesse d'un tel OTP dépend grandement de celle du
**générateur pseudo aléatoire** utilisé pour sa génération. Ici,
nous utilisons le module `random` de python, qui n'est pas très
robuste bien que pratique.

Je vous conseille à ce sujet d'aller consulter le github suivant
qui propose une méthode de prédiction du module `random` inclus
dans python : [**randcrack** par **tna0y**](https://github.com/tna0y/Python-random-module-cracker)

# Faille : Oubli de valeurs

Dans le programme précédent, nous avons pu voir que les octets
constituant l'OTP pouvaient prendre **toutes les valeurs
possibles** d'un octet.

Il existe des cas ou des valeurs sont **oubliées**. par valeurs
oubliées, on entend que les octets de l'OTP prennent des valeurs
dans un intervalle plus petit que `[0, 255]`.

Dans le cas ou nous aurions **moins de 256 valeurs** possibles
pour les octets de l'OTP, la situation est la même pour le
message chiffré.

## Exemple d'oubli de valeur

Nous avons l'octet `0x05`, l'intervalle des valeurs prises par
les octets de l'OTP est `[0, 254]`, il manque 255.

Cela signifie que l'octet chiffré pourra prendre toutes les
valeurs dans l'intervalle `[0, 255]` sauf `XOR(0x05, 255) = 250`.

Nous pouvons alors retrouver le message clair à partir d'un
échantillon **assez grand** de messages chiffrés.

En effet, si nous connaissons la valeur oublié et que nous avons
en notre possession un échantillon assez grand de messageschiffrés
(même message clair mais OTP **regénéré à chaque chiffrement**
sinon cela sera inutile), nous pouvons éliminer **toutes les
valeurs possibles** de l'octet chiffré.

Une fois qu'il ne reste plus qu'une valeur, 250 en l'occurence,
il suffit de faire un XOR entre cette valeur et la valeur oubliée
à savoir 255 : `XOR(250, 255) = 5`.

On voit donc qu'on peut obtenir la totalité d'un message plus
long par un procédé similaire. Malheureusement, cette méthode
requiert l'utilisation de la force brute, ce qui la rend non
faisable dans un contexte ou nous aurions le droit à trop peu
de requête à un service par exemple.

De plus, nous ne pouvons pas estimer la taille nécessaire de
l'échantillon, car une valeur pourrait apparaître en deux
essais, ou ne pourrait pas apparaître en 1 million.

Il est important de faire attention à de telles failles à côté
de laquelle nous pourrions facilement passer lors du
développement d'une application.