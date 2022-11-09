#!/bin/bash

set -exuo pipefail

[ -d ./ubuntu ] || mkdir ubuntu;
docker build -t optee_build .
DIR=$(pwd)

echo "cd $DIR/optee && $@" | docker run -v $DIR:$DIR -v $DIR/ubuntu:/home/ubuntu -i optee_build bash
