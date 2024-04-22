# Utilisation de l'image Ubuntu la plus récente
FROM ubuntu:latest

# Eviter les problèmes d'interface utilisateur pendant l'installation
ARG DEBIAN_FRONTEND=noninteractive

# Mise à jour des paquets et installation des dépendances nécessaires
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Répertoire de travail
WORKDIR /workspace

# Cloner le dépôt et installer les dépendances
RUN git clone https://github.com/SherlockFS/SherlockFS.git shlkfs && \
    cd shlkfs && \
    git checkout dev && \
    cp .github/apt_sources_list/ubuntu-noble.list /etc/apt/sources.list.d/ && \
    bash ./dependencies.sh --with-tests

# Nettoyer
RUN rm -rf shlkfs
