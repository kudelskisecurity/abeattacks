#!/bin/sh

docker build -t abeattacks .
docker run -p 8888:8888 abeattacks

