# Using the latest Ubuntu image
FROM ubuntu:latest

# Avoid UI issues during installation
ARG DEBIAN_FRONTEND=noninteractive

# Update packages and install necessary dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /workspace

# Clone the repository and install dependencies
RUN git clone https://github.com/SherlockFS/SherlockFS.git && \
    cd SherlockFS && \
    git checkout dev && \
    cp .github/apt_sources_list/ubuntu-noble.list /etc/apt/sources.list.d/ && \
    apt-get update && \
    bash ./dependencies.sh --with-tests

# Set the working directory for the SherlockFS repository
WORKDIR /workspace/SherlockFS

# Configure the container to start a Bash terminal upon launch
CMD ["bash"]
