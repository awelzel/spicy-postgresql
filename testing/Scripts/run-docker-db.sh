#!/bin/bash

docker run -d --name postgres  -e POSTGRES_DB=zeek -e POSTGRES_USER=zeek -e POSTGRES_PASSWORD=zeek --network=host --rm -it postgres
