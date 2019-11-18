FROM ingomuellernet/buildenv


RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libtinfo-dev libz-dev libgmp-dev libedit-dev \
    build-essential python mono-complete mono-xbuild \
    fsharp nuget mono-reference-assemblies-4.0

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    tzdata

RUN mkdir /opt/kittel && \
    cd /opt/kittel && \
    git clone https://github.com/hkhlaaf/llvm2kittel.git && \
    cd /opt/kittel/llvm2kittel && \
    mkdir build && cd build && \
    cmake -DLLVM_CONFIG_EXECUTABLE=/usr/bin/llvm-config-3.6 .. && \
    make && chmod +x llvm2kittel

RUN cd /opt && git clone https://github.com/mmjb/T2.git T2

RUN cd /opt && git clone https://bitbucket.org/spacer/code

RUN cd /opt/code && \
    git checkout spacer-t2 && \
    CC=clang3.9 CXX=clang++-3.9 python scripts/mk_make.py && \
    cd build && make && \
    cd /opt/code/src/api/dotnet/ && \
    xbuild /property:Configuration=Release && \
    cp /opt/code/src/api/external/Microsoft.Z3.* /opt/T2/src && \
    cp /opt/code/build/libz3.* /opt/T2/src

RUN cd /opt/T2/src && \
    mozroots --import --sync && \
    nuget restore && \
    chmod +x packages/FsLexYacc.*/build/*exe && \
    xbuild /property:Configuration=Release

# This line serves to install required 
# header to compile FRRouting plugins
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git autoconf automake libtool make libreadline-dev texinfo \
    pkg-config libpam0g-dev libjson-c-dev bison flex python3-pytest \
    libc-ares-dev python3-dev libsystemd-dev python-ipaddress python3-sphinx \
    install-info build-essential libsystemd-dev libsnmp-dev perl libcap-dev

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libpcre3-dev libpcre2-dev libpcre++-dev 

RUN wget https://github.com/CESNET/libyang/archive/debian/libyang-0.16.105-1.tar.gz -O - \
    | tar -C /opt -xz && \
    cd /opt/libyang-debian-libyang-0.16.105-1 && mkdir build && cd build && \
    cmake -DENABLE_LYD_PRIV=ON -DCMAKE_INSTALL_PREFIX:PATH=/usr \
      -D CMAKE_BUILD_TYPE:String="Release" -DENABLE_CACHE=OFF .. && \
    make && make install

RUN chmod +x /opt/T2/src/bin/Release/T2.exe

RUN printf "#!/bin/bash \n#T2 easy#\nif [ "$*" != "" ] ; then\n    mono /opt/T2/src/bin/Release/T2.exe \$*\nfi\n" \
    > /opt/T2/src/bin/Release/T2 && chmod +x /opt/T2/src/bin/Release/T2

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    vim nano

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 python3-ply

COPY mini_parser.py /opt/mini_parser/mini_parser
RUN chmod +x /opt/mini_parser/mini_parser
ENV MINIPARSER /opt/mini_parser/mini_parser

RUN printf "#!/usr/bin/env bash\nFUNNAME=\$2\nFULLNAME=\$1\nBASENAME=\$(basename \$1 .c)\nCFLAGS=\$3\nclang-3.6 -Wall -Wextra \$CFLAGS -c -emit-llvm  \$FULLNAME -o \$BASENAME.bc &>/dev/null && llvm2kittel --eager-inline  --function=\$FUNNAME --dump-ll --no-slicing --t2 \$BASENAME.bc | sed -r 's/^\/\/\/\*\*\* \S+ \*\*\*\/\/\/$//g' - | \$MINIPARSER 2>/dev/null > \$BASENAME.t2 && T2 -input_t2 \$BASENAME.t2 -termination -print_proof\n" > /usr/bin/T2-proof && \
chmod +x /usr/bin/T2-proof

ENV PATH /opt/kittel/llvm2kittel/build:/opt/T2/src/bin/Release/:${PATH}

