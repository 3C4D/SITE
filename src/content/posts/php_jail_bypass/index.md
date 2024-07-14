---
title: PHP Jail - Strings/Fonctions
published: 2023-09-18
description: Construire des chaînes de caractères / Exécuter des fonctions
tags: [php, jail, bypass]
image : /images/php_jail_bypass/prison_php.jpg
category: Articles
draft: false
---

# PHP Jail (et toutes les Jails)

Le principe d'une Jail (ou prison) PHP, de même que pour d'autres
prisons (en Bash, Python, Javascript, etc.) est que vous êtes enfermés
dans un programme. Le but ? En sortir avec très peu de moyens, des
caractères, chaînes de caractères ou bien des fonctions peuvent être
filtrés, il va donc falloir faire preuve d'ingéniosité pour y
arriver.

## Exemple d'une prison PHP

Un exemple de prison PHP est le suivant, tiré du CTF `Ringzer0ctf` de
2019. L'épreuve fut sobrement intitulée `PHP Jail 1` :

[(Write-up de cette épreuve par **pwn4magic**)](https://medium.com/@pwn4magic/ringzer0ctf-php-jail-1-1076a97ece98)

```php
<?php
array_shift($_SERVER['argv']);
$var = implode(" ", $_SERVER['argv']);

if($var == null) die("PHP Jail need an argument\n");

function filter($var) {
        if(preg_match('/(`|open|exec|pass|system|\$|\/)/i', $var)) {
                return false;
        }
        return true;
}
if(filter($var)) {
        eval($var);
        echo "Command executed";
} else {
        echo "Restricted characters has been used";
}
echo "\n";
?>
```

on peut voir ici que le programme n'est pas une boucle qui demanderait
un input mais un programme que le serveur pourrait par exemple exécuter
à chaque requête sur une certaine URL. Pour simplifier l'exemple,
considérons que la variable `argv` est un input local.

Ici, plusieurs mots et caractères sont filtrés tels que `open` qui
pourrait nous permettre d'ouvrir un fichier du côté du serveur ou bien
`system`, qui est une fonction que l'on pourrait utiliser pour exécuter des
commandes systèmes telles qu'ouvrir un shell.

Si la commande passe dans le filtre sans l'alarmer, elle sera évaluée à l'aide
de la fonction `eval`, exécutant du code PHP sous forme de chaîne de
caractères.

L'outil de filtrage est une expression régulière, `preg_match` renverra
vrai s'il trouve dans la variable `$var` une sous-chaîne correspondant à
l'expression. Nous n'allons pas pouvoir jouer sur les majuscules/minuscules
car le `i` à la fin de l'expression indique que celle-ci n'est pas sensible
à la casse (`SyStEm` ne passera plus que `system`).

L'épreuve nous dit :

```
Flag is located at /home/level1/flag.txt
```

Une solution pourrait donc être : `"echo file_get_contents('flag.txt');"`,
ce qui affichera dans le contenu du fichier.

Nous allons voir dans la partie suivante que le filtre ne nous empêche en
réalité pas du tout d'exécuter toutes les fonctions de PHP.

## Exécution de code à l'aide de la fonction preg_replace

`preg_replace` est une fonction, à l'image de `preg_match`, qui permet de
détecter dans une chaîne de caractères la présence de mots reconnus par
une expression régulière donnée. À la différence de `preg_match`, les
mots reconnus seront remplacés par une chaîne de caratères choisie au
préalable.

Prototype (très simplifié) :
```
preg_replace(
  string $pattern,
  string $replacement,
  string $subject,
  ...
)
```

Une subtilité qui fait de `preg_replace` une fonction très utile et
surtout très sensible (Cf les épreuves sur cette fonction en
particulier) est son premier paramètre. En effet, le pattern se
compose d'une expression régulière `/.../` puis d'un caractère final.
Nous avons déjà vu `i`, mais celui qui nous intéresse est `e`.

Si le caractère `e` est utilisé, la chaîne `$replacement` sera évaluée
comme du PHP avant de remplacer le pattern trouvé dans `$subject`.

Exemple trivial : `preg_replace("/bonjour/e", "system('sh')", "bonjour")`

Ici le pattern sera reconnu ("bonjour" est une sous-chaîne de "bonjour").
Ensuite, la fonction donc exécuter la commande
`system('cat /etc/passwd')` qui nous donnera un shell. Nous aurions
aussi pu ouvrir un reverse-shell si exécuté sur un serveur distant ou
afficher un fichier à l'aide de `cat` par exemple.

Heureusement, l'option `e` n'est plus supportée sur les dernières
versions de PHP.

## Construction de chaînes de caractères non filtrées

Afin d'utiliser la fonction `preg_replace`, il va nous falloir
construire des chaînes de caractères non filtrées. Nous pouvons
pour cela combiner plusieurs techniques. En voici quelques-unes.

### Fonction implode pour le type array

La fonction `implode` permet de fusionner des tableaux de chaînes
de caractères en une seule chaîne.

Exemple : `implode(array("sys","tem"))` donnera la chaîne `system`

Nous avons ici un moyen de passer les chaînes filtrées. La
technique suivante nous permettra de passer aussi des caractères
filtrés, ce que cette technique ne permet pas.

### Forger des caractères à l'aide d'opérations logiques ou de variables

Les opérations logiques telles que le ET (`&`), le OU (`|`) ou bien
le XOR (`^`) peuvent nous permettre de forger des caractères
filtrés à l'aide de caractères non filtrés ou de variables
existantes.

Exemple : `'a' ^ 'Z'` donnera le caractère `;`

Exemple 2 : `'a' & 'Z'` donnera le caractère `@`

Exemple 3 :

Nous possédons une variable connue `$file` contenant la chaîne
"./jail.php".

Nous pouvons indicer cette variable pour récupérer les caractères
'.' (`$file[0]`) ou bien '/' (`$file[1]`). Évidemment, nous
pouvons utiliser ces caractères potentiellement déjà filtrés
pour forger d'autres caractères filtrés à l'aide des opérations
logiques.

## Conclusion

Pour conclure cet article, je vous dirais que ceci n'est qu'une
infime partie de tous les bypass possibles dans le cas d'une
Jail PHP, mais je trouvais ces techniques très intéressantes à
présenter car elle pourraient être utile pour la plupart des prisons,
particulièrement celles permettant de forger des chaînes arbitraires.
