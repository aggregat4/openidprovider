#!/bin/bash

# This will build the program inside a docker container so that it links against an older
# version of libc and makes it easier to run on somewhat older servers
docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:1.21 scripts/build.sh
