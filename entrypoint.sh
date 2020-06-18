#!/bin/sh

java -cp `cat /app/cp.txt` SoapClientTest "$@"