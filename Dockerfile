#
# Spiderfoot Dockerfile
#
# http://www.spiderfoot.net
#
# Written by: Michael Pellon <m@pellon.io>
# Updated by: Chandrapal <bnchandrapal@protonmail.com>
# Updated by: Steve Micallef <steve@binarypool.com>
#
# Usage:
#
#   sudo docker build -t spiderfoot .
#   sudo docker run -it -p 8080:8080 spiderfoot

# Pull the base image.
FROM alpine:3.7

COPY requirements.txt .

# Install pre-requisites.
RUN apk --update add \
  curl \
  git \
  swig \
  openssl-dev \
  libxslt-dev \
  tinyxml-dev \
  py-lxml \
  linux-headers \
  musl-dev

RUN apk --update add --virtual build-dependencies python-dev py-pip gcc \
  && pip install wheel && pip install -r requirements.txt

# Create a dedicated/non-privileged user to run the app.
RUN addgroup spiderfoot && \
    adduser -G spiderfoot -h /home/spiderfoot -s /sbin/nologin \
            -g "SpiderFoot User" -D spiderfoot && \
    rmdir /home/spiderfoot

ENV SPIDERFOOT_VERSION 2.11.0

# Download the specified release.
WORKDIR /home
RUN curl -sSL https://github.com/smicallef/spiderfoot/archive/v$SPIDERFOOT_VERSION-final.tar.gz \
  | tar -v -C /home -xz \
  && mv /home/spiderfoot-$SPIDERFOOT_VERSION-final /home/spiderfoot \
  && chown -R spiderfoot:spiderfoot /home/spiderfoot

USER spiderfoot
WORKDIR /home/spiderfoot

EXPOSE 8080

# Run the application.
ENTRYPOINT ["/usr/bin/python"] 
CMD ["./sf.py", "0.0.0.0:8080"]
