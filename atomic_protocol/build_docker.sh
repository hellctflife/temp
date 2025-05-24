#!/bin/bash
docker build -t atomic_protocol .
docker run  --name=atomic_protocol --rm -p 1337:1337 -it atomic_protocol