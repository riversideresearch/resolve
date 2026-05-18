FROM ubuntu:latest as installdeps

RUN dpkg --add-architecture i386

RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y \
      git \
      python3.8 \
      python3-pip \
      wget \
      curl \
      build-essential \
      libtinfo-dev \
      lsb-release \
      zlib1g-dev \
      ccache \
      cmake \
      clang \
      libc6-dev:i386 \
      g++-multilib \
      # extra
      ninja-build

RUN mkdir -p /resolve-patch/tob-vcpkg
WORKDIR /resolve-patch/tob-vcpkg

RUN curl -LO https://github.com/lifting-bits/cxx-common/releases/latest/download/vcpkg_ubuntu-22.04_llvm-16_amd64.tar.xz && \
    tar -xJf vcpkg_ubuntu-22.04_llvm-16_amd64.tar.xz

# IMPORTANT
COPY . /resolve-patch
RUN printf "" > /resolve-patch/remill/cmake/git_watcher.cmake
RUN rm -rf /resolve-patch/remill/build
RUN rm -rf /resolve-patch/remill/dependencies/build
RUN rm -rf /resolve-patch/remill/dependencies/install

FROM installdeps as build

RUN mkdir -p /resolve-patch/remill/build
WORKDIR /resolve-patch/remill
RUN cmake -G Ninja -S dependencies -B dependencies/build -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUSE_EXTERNAL_LLVM=ON
RUN cmake --build dependencies/build
RUN cmake -G Ninja -B build -DCMAKE_PREFIX_PATH:PATH=$(pwd)/dependencies/install -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
RUN cmake --build build
RUN cmake --install

RUN mkdir -p /resolve-patch/anvill/anvill-build
WORKDIR /resolve-patch/anvill/anvill-build

ENV VCPKG_ROOT=/resolve-patch/tob-vcpkg/vcpkg_ubuntu-22.04_llvm-16_amd64

RUN cmake .. \
    -DVCPKG_ROOT=/resolve-patch/tob-vcpkg/vcpkg_ubuntu-22.04_llvm-16_amd64 \
    -Dremill_DIR=/resolve-patch/remill \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_TOOLCHAIN_FILE=/resolve-patch/tob-vcpkg/vcpkg_ubuntu-22.04_llvm-16_amd64/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_TARGET_TRIPLET=x64-linux-rel

RUN make -j$(nproc)

RUN make install