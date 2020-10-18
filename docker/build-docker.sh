#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-ruxcryptopay/ruxcryptod-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/ruxcryptod docker/bin/
cp $BUILD_DIR/src/ruxcrypto-cli docker/bin/
cp $BUILD_DIR/src/ruxcrypto-tx docker/bin/
strip docker/bin/ruxcryptod
strip docker/bin/ruxcrypto-cli
strip docker/bin/ruxcrypto-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker
