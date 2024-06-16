# SherlockFS v1 - Système de fichiers chiffré

![SherlockFS logo](images/SherlockFS_logo.png)

**Branche de développement**

[![DEV branch tests](https://github.com/SherlockFS/SherlockFS/actions/workflows/test_suite.yml/badge.svg?branch=dev)](https://github.com/SherlockFS/SherlockFS/actions/workflows/test_suite.yml)

**Branche de production**

[![MAIN branch tests](https://github.com/SherlockFS/SherlockFS/actions/workflows/test_suite.yml/badge.svg?branch=main)](https://github.com/SherlockFS/SherlockFS/actions/workflows/test_suite.yml)

## Introduction

SherlockFS est un système de fichiers chiffré, s'inspirant des principes de FAT et LUKS. Conçu pour plusieurs utilisateurs, il offre une solution sécurisée pour le stockage de fichiers sur un périphérique. La version actuelle (v1) de SherlockFS est une implémentation logicielle basée sur FUSE.

## Fonctionnalités

Actuellement, SherlockFS propose quatre outils principaux :

1. `shlkfs.mkfs` : Utilisé pour initialiser un périphérique avec le système de fichiers SherlockFS.
2. `shlkfs.mount` : Permet de monter un système de fichiers formaté en SherlockFS.
3. `shlkfs.useradd` : Permet d'ajouter un nouvel utilisateur (via sa clé publique) en utilisant les accès d'un utilisateur existant (sa clé privée).
4. `shlkfs.userdel` : Permet de supprimer un utilisateur du système de fichiers.

## Prérequis

Avant de démarrer, il est nécessaire d'installer les dépendances. Exécutez `bash dependencies.sh`. Ce script est compatible uniquement avec les gestionnaires de paquets `apt` ou `pacman`.

> Étant donné que ce script installe des paquets sur le système, il doit être exécuté avec les privilèges super-utilisateur (`root`).

## Compilation

Pour compiler les programmes :

- `make` : Compile tous les programmes.
- `make shlkfs.mkfs` : Compile uniquement le programme `shlkfs.mkfs`.
- `make shlkfs.mount` : Compile uniquement le programme `shlkfs.mount`.
- `make shlkfs.useradd` : Compile uniquement le programme `shlkfs.useradd`.
- `make shlkfs.userdel` : Compile uniquement le programme `shlkfs.userdel`.
- `make check`: Compile tous les programmes et exécute les tests unitaires.
- `make clean` : Supprime les fichiers générés par la compilation.
- `make clean.all` : Supprime le dossier `build/`.

Les exécutables compilés se trouveront dans le dossier `build/`.

> Si vous souhaitez compiler les programmes avec des options de débogage, vous devez au préalable définir la variable d'environnement `SHLKFS_DEBUG=1`.

## Utilisation des utilitaires

### `shlkfs.mkfs`

```shell

# ./build/shlkfs.mkfs

SherlockFS v1 - Format a device
        Usage: ./build/shlkfs.mkfs <device> [label]
```

`shlkfs.mkfs` permet d'initialiser un périphérique avec le système de fichiers SherlockFS. Il prend en paramètre le chemin vers le périphérique à formater, et éventuellement un label (nom du système de fichiers). Si le périphérique est déjà formaté avec SherlockFS, il vous sera demandé si vous souhaitez le reformater.

Une fois le formatage effectué, les clés publiques et privées utisées lors du formatage seront sauvegardées dans le dossier `~/.shlkfs` (`public.pem` et `private.pem`). Ces clés sont nécessaires pour monter le périphérique et ajouter de nouveaux utilisateurs au système de fichiers. **Il est donc important de les conserver en lieu sûr et de ne pas les perdre.**

### `shlkfs.mount`

```shell
# ./build/shlkfs.mount

SherlockFS v1 - Mounting a SherlockFS file system
        Usage: ./build/shlkfs.mount [-k|--key <PRIVATE KEY PATH>] [-v|--verbose] <DEVICE> [FUSE OPTIONS] <MOUNTPOINT>
```

`shlkfs.mount` permet de monter un système de fichiers formaté en SherlockFS avec FUSE. Il prend plusieurs paramètres :

- `-k` ou `--key` : Le chemin vers la clé privée à utiliser pour le montage. Cette clé doit correspondre à une clé enregistrée sur le périphérique. Si cette option n'est pas spécifiée, `shlkfs.mount` cherchera à utiliser la clé privée `~/.shlkfs/private.pem`.
- `-v` ou `--verbose` : Active le mode verbeux, qui affiche des informations supplémentaires pendant toute la durée de vie du système de fichiers monté.
- `<DEVICE>` : Le chemin vers le périphérique à monter. Ce périphérique doit être formaté avec SherlockFS.
- `[FUSE OPTIONS]` : Des options supplémentaires pour FUSE, si nécessaire.
- `<MOUNTPOINT>` : Le point de montage où le système de fichiers doit être monté.

Une fois le système de fichiers monté, vous pouvez interagir avec lui comme avec n'importe quel autre système de fichiers sur votre machine. Assurez-vous de disposer de la clé privée correspondante avant de tenter de monter le système de fichiers. Si vous perdez cette clé, vous ne pourrez pas accéder aux données sur le système de fichiers SherlockFS.

### `shlkfs.useradd`

```shell

# ./build/shlkfs.useradd

SherlockFS v1 - Adding user to device keys storage
        Usage: ./build/shlkfs.useradd <device> <other user public key path> [registred user private key path]
```

`shlkfs.useradd` permet d'ajouter un nouvel utilisateur au système de fichiers. Il prend en paramètre le chemin vers le périphérique formaté avec SherlockFS, le chemin vers la clé publique de l'utilisateur à ajouter et éventuellement le chemin vers la clé privée d'un utilisateur déjà enregistré sur le périphérique. Si la clé privée n'est pas spécifiée, `shlkfs.useradd` cherchera à utiliser la clé privée de l'utilisateur courant (celui qui exécute le programme): `~/.shlkfs/private.pem`.

### `shlkfs.userdel`

```shell
SherlockFS v1 - Deleting user from device keys storage
        Usage: ./build/shlkfs.userdel <device> <deleting user public key path> [registred user private key path]
```

`shlkfs.userdel` permet de supprimer un utilisateur du système de fichiers. Il prend en paramètre le chemin vers le périphérique formaté avec SherlockFS, le chemin vers la clé publique de l'utilisateur à supprimer et éventuellement le chemin vers la clé privée d'un utilisateur déjà enregistré sur le périphérique. Si la clé privée n'est pas spécifiée, `shlkfs.userdel` cherchera à utiliser la clé privée de l'utilisateur courant (celui qui exécute le programme): `~/.shlkfs/private.pem`.

## Utilisation avec Docker

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/SherlockFS/SherlockFS/tree/dev?quickstart=1)

### Création de l'image Docker

Pour créer l'image Docker de SherlockFS, vous pouvez exécuter la commande suivante depuis la racine du dépôt du projet :

```shell
docker build -t shlkfs .
```

> Cette image contient toutes les dépendances nécessaires pour compiler et exécuter SherlockFS.

### Démarrage du conteneur de développement

Pour démarrer un conteneur Docker avec l'image de SherlockFS, vous pouvez exécuter la commande suivante depuis la racine du dépôt du projet :

```shell
docker run --privileged -it -v $(pwd):/workspace/SherlockFS shlkfs
```

> Cette commande monte le dépôt du projet situé dans le répertoire courant dans le conteneur Docker, dans le répertoire `/workspace/SherlockFS`.
