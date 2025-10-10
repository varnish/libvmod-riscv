#!/bin/bash

curl http://127.0.0.1:8000/cat -H "Host: rusty.com" -o /tmp/token.tok

curl -D - -X POST http://127.0.0.1:8000/verify -H "Host: rusty.com" --data-binary @/tmp/token.tok
