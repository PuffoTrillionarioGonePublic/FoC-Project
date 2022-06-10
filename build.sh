#!/bin/sh

docker build -t openssl-boost .
docker run --rm \
	-v $(pwd):/app \
	-u $(id -u ${USER}):$(id -g ${USER}) \
	openssl-boost \
	bash -c "mkdir -p app/build && cd app/build && cmake .. && make -j$(nproc)"