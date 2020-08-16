#!/bin/sh
if ! command -v openssl >/dev/null 2>&1 ; then
  echo "Error: Could not find openssl in \$PATH: $PATH"
  exit 1
fi

if test -f spiderfoot.key; then
  echo "Error: spiderfoot.key already exists"
  exit 1
fi

if test -f spiderfoot.crt; then
  echo "Error: spiderfoot.crt already exists"
  exit 1
fi

openssl req -new -newkey rsa:4096 -sha256 -x509 -days 365 -nodes -out spiderfoot.crt -keyout spiderfoot.key -subj "/CN=localhost"

chmod 600 spiderfoot.crt
chmod 600 spiderfoot.key
