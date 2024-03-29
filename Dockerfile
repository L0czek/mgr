FROM ubuntu:22.04
RUN apt -y update && DEBIAN_FRONTEND=noninteractive TZ=Europe/Warsaw apt -y install \
  adb \
  acpica-tools \
  autoconf \
  automake \
  bc \
  bison \
  build-essential \
  ccache \
  cscope \
  curl \
  device-tree-compiler \
  expect \
  fastboot \
  flex \
  ftp-upload \
  gdisk \
  libattr1-dev \
  libcap-dev \
  libfdt-dev \
  libftdi-dev \
  libglib2.0-dev \
  libgmp3-dev \
  libhidapi-dev \
  libmpc-dev \
  libncurses5-dev \
  libpixman-1-dev \
  libssl-dev \
  libtool \
  make \
  mtools \
  netcat \
  ninja-build \
  python3-cryptography \
  python3-pip \
  python3-pyelftools \
  python3-serial \
  python-is-python3 \
  rsync \
  unzip \
  uuid-dev \
  xdg-utils \
  xterm \
  xz-utils \
  zlib1g-dev \
  git \
  wget \
  curl \
  cpio
RUN useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 ubuntu
USER ubuntu
WORKDIR /home/ubuntu
