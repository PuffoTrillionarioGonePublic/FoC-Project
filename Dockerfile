FROM ubuntu:21.10

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update
# RUN apt install -y tzdata
RUN  apt-get update
RUN  apt-get install -y \
    gcc-11 \
    g++-11 \
    gdb \
    cmake \
    autoconf \
    automake \
    make \
	valgrind

RUN apt-get install -y libssl-dev
RUN apt-get install -y libboost-all-dev

ENV CXX=g++-11

# docker run --entrypoint /bin/bash -p 0.0.0.0:9000:9000 --mount type=bind,source=${PWD},destination=/FoC-Project --env CXX=g++-11 -it --rm cmake-boost