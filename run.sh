#!/bin/bash
docker build -t auth .
docker run -d -p 5000:5000 auth