# SherlockFS v1 - Système de fichiers chiffré

![SherlockFS logo](images/SherlockFS_logo.png)

**Branche de développement**

[![DEV branch tests](https://github.com/SherlockFS/SherlockFS/actions/workflows/test_suite.yml/badge.svg?branch=dev)](https://github.com/SherlockFS/SherlockFS/actions/workflows/test_suite.yml)

**Branche de production**

[![MAIN branch tests](https://github.com/SherlockFS/SherlockFS/actions/workflows/test_suite.yml/badge.svg?branch=main)](https://github.com/SherlockFS/SherlockFS/actions/workflows/test_suite.yml)

## Introduction

SherlockFS est un système de fichiers chiffré, s'inspirant des principes de FAT et LUKS. Conçu pour plusieurs utilisateurs, il offre une solution sécurisée pour le stockage de fichiers sur un périphérique. La version actuelle (v1) de SherlockFS est une implémentation logicielle basée sur FUSE, bien qu'elle soit encore en cours de développement.

## Fonctionnalités

Actuellement, SherlockFS propose deux outils principaux :

1. `shlkfs_formater` : Utilisé pour initialiser un périphérique avec le système de fichiers SherlockFS.
2. `shlkfs_adduser` : Permet d'ajouter un nouvel utilisateur (via sa clé publique) en utilisant les accès d'un utilisateur existant (sa clé privée).
3. `shlkfs_deluser` : Permet de supprimer un utilisateur du système de fichiers.

Un quatrième outil, `shlkfs_mount`, est prévu pour une intégration future après la finalisation de l'implémentation FUSE.

## Prérequis

Avant de démarrer, il est nécessaire d'installer les dépendances. Exécutez `bash dependencies.sh`. Ce script est compatible uniquement avec les gestionnaires de paquets `apt` ou `pacman`.

## Compilation

Pour compiler les programmes :

- `make` : Compile tous les programmes.
- `make shlkfs_formater` : Compile uniquement le programme `shlkfs_formater`.
- `make shlkfs_adduser` : Compile uniquement le programme `shlkfs_adduser`.
- `make shlkfs_deluser` : Compile uniquement le programme `shlkfs_deluser`.
- `make check`: Compile tous les programmes et exécute les tests unitaires.
- `make clean` : Supprime les fichiers générés par la compilation.
- `make clean_all` : Supprime le dossier `build/`.

Les exécutables compilés se trouveront dans le dossier `build/`.

## Utilisation des utilitaires

### `shlkfs_formater`

```shell

# ./build/shlkfs_formater

SherlockFS v1 - Format a device
        Usage: ./build/shlkfs_formater <device>
```

`shlkfs_formater` permet d'initialiser un périphérique avec le système de fichiers SherlockFS. Il prend en paramètre le chemin vers le périphérique à formater. Le périphérique peut être vide mais doit être non monté. Si le périphérique est déjà formaté avec SherlockFS, il vous sera demandé si vous souhaitez le reformater.

Une fois le formatage effectué, les clés publiques et privées utisées lors du formatage seront sauvegardées dans le dossier `~/.sherlockfs` (`public.pem` et `private.pem`). Ces clés sont nécessaires pour monter le périphérique et ajouter de nouveaux utilisateurs au système de fichiers. **Il est donc important de les conserver en lieu sûr et de ne pas les perdre.**

### `shlkfs_adduser`

```shell

# ./build/shlkfs_adduser

SherlockFS v1 - Adding user to device keys storage
        Usage: ./build/shlkfs_adduser <device> <other user public key path> [registred user private key path]
```

`shlkfs_adduser` permet d'ajouter un nouvel utilisateur au système de fichiers. Il prend en paramètre le chemin vers le périphérique formaté avec SherlockFS, le chemin vers la clé publique de l'utilisateur à ajouter et éventuellement le chemin vers la clé privée d'un utilisateur déjà enregistré sur le périphérique. Si la clé privée n'est pas spécifiée, `shlkfs_adduser` cherchera à utiliser la clé privée de l'utilisateur courant (celui qui exécute le programme), dans le dossier `~/.sherlockfs/`.

### `shlkfs_deluser`

```shell
SherlockFS v1 - Deleting user from device keys storage
        Usage: ./build/shlkfs_deluser <device> <deleting user public key path> [registred user private key path]
```

`shlkfs_deluser` permet de supprimer un utilisateur du système de fichiers. Il prend en paramètre le chemin vers le périphérique formaté avec SherlockFS, le chemin vers la clé publique de l'utilisateur à supprimer et éventuellement le chemin vers la clé privée d'un utilisateur déjà enregistré sur le périphérique. Si la clé privée n'est pas spécifiée, `shlkfs_deluser` cherchera à utiliser la clé privée de l'utilisateur courant (celui qui exécute le programme), dans le dossier `~/.sherlockfs/`.

## Utilisation avec Docker

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/SherlockFS/SherlockFS/tree/dev?quickstart=1)

### Création de l'image Docker

Pour créer l'image Docker de SherlockFS, vous pouvez exécuter la commande suivante depuis la racine du dépôt du projet :

```shell
docker build -t shlkfs .
```

> Cette image contient toutes les dépendances nécessaires pour compiler et exécuter SherlockFS.

### Démarrage du conteneur Docker

Pour démarrer un conteneur Docker avec l'image de SherlockFS, vous pouvez exécuter la commande suivante depuis la racine du dépôt du projet :

```shell
docker run -it -v $(pwd):/workspace/SherlockFS shlkfs
```

> Cette commande monte le dépôt du projet situé dans le répertoire courant dans le conteneur Docker, dans le répertoire `/workspace/SherlockFS`.

## Développement

### Structure du projet

Le projet est divisé en plusieurs dossiers :

- `src/` : Contient les sources des programmes. La racine de ce dossier contient les sources "`main()`" de chaque programme (`shlkfs_formater`, `shlkfs_adduser`, etc.)
  - `src/fs`: Contient les sources purement relatives au système de fichiers.
  - `src/fuse`: Contient les sources relatives à l'implémentation FUSE.
- `include/` : Contient les en-têtes des programmes.
- `build/` : Contient les exécutables compilés.
- `tests/` : Contient les tests unitaires.
  - `tests/criterion` : Contient les sources de la bibliothèque de tests unitaires Criterion.
  - `tests/test_main.c` : Fichier de test (un peu sale) qui permet de tester diverses fonctionnalités (utilisable avec `make test_main`, puis `./build/test_main`).
