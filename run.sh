#!/bin/bash
docker build -t auth .
docker run -it -p 5000:5000 auth flask run --host=0.0.0.0