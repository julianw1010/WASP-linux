#!/bin/bash
set -e

# Kernel Build Environment Setup for Ubuntu
# Installs all dependencies needed for building the Linux kernel

sudo apt update

sudo apt install -y \
    build-essential \
    bc \
    bison \
    binutils-dev \
    ccache \
    curl \
    dwarves \
    fakeroot \
    flex \
    git \
    libbabeltrace-dev \
    libaudit-dev \
    libcap-dev \
    libdw-dev \
    libelf-dev \
    libncurses-dev \
    libnuma-dev \
    libperl-dev \
    libslang2-dev \
    libssl-dev \
    libtraceevent-dev \
    libtracefs-dev \
    libunwind-dev \
    pkg-config \
    python3-dev \
    rsync \
    systemtap-sdt-dev \
    wget

cp wasp.config .config
