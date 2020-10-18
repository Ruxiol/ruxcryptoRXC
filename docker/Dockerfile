FROM debian:stretch
LABEL maintainer="RuxCrypto Developers <dev@ruxcrypto.org>"
LABEL description="Dockerised RuxCryptoCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
