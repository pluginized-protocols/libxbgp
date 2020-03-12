FROM ubuntu:18.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y apt-utils

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libgmp-dev libgmp3-dev libgmpxx4ldbl libmpfr-dev \
    libmpc-dev libcloog-isl-dev git gnat-7 \
    libgnat-7 libncurses-dev flex bison openssl \
    libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev \
    autoconf make perl libisl-0.18-dev build-essential

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y apt-utils

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y texinfo

# Compile binutils
WORKDIR /opt
RUN git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
WORKDIR /opt/binutils-build

RUN /opt/binutils/configure \
--prefix=/usr/local \
--target=bpf \
--enable-deterministic-archives \
--enable-gold \
--enable-ld \
--enable-libada \
--enable-libssp \
--enable-lto \
--enable-plugins \
--enable-relro \
--enable-shared \
--enable-threads \
--disable-werror \
--with-pic \
--with-system-zlib \
--disable-nls \
--with-sysroot

RUN make && make install

# Compile gcc
WORKDIR /opt
RUN git clone --depth 1 git://gcc.gnu.org/git/gcc.git gcc
WORKDIR /opt/gcc

WORKDIR /opt/gcc-build
RUN /opt/gcc/configure \
--disable-bootstrap \
--enable-languages=c,c++,objc,obj-c++,lto,d,jit \
--prefix=/usr/local \
--mandir=/usr/local/share/man \
--infodir=/usr/local/share/info \
--enable-shared \
--enable-host-shared \
--disable-threads \
--enable-checking=release \
--enable-multilib \
--with-system-zlib \
--without-headers \
--enable-lto \
--disable-nls \
--enable-__cxa_atexit \
--disable-libunwind-exceptions \
--enable-gnu-unique-object \
--enable-linker-build-id \
--enable-plugin \
--enable-initfini-array \
--with-isl \
--enable-offload-targets=nvptx-none \
--enable-checking=release \
--without-cuda-driver \
--enable-gnu-indirect-function \
--enable-cet \
--target=bpf

RUN make && make install

RUN rm -rf /opt/gcc-build /opt/gcc /opt/binutils /opt/binutils-build

RUN ldconfig /usr/local/lib

WORKDIR /root

### how to use the compiler
# docker build -t ebpf_gcc .
# docker run -v /home/thomas/ebpf_code:/root/host -it ebpf_gcc bpf-gcc host/test.c

