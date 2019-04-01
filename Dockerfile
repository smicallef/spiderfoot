#
# Spiderfoot Dockerfile
#
# http://www.spiderfoot.net
#
# Written by: Michael Pellon <m@pellon.io>
# Updated by: Chandrapal <bnchandrapal@protonmail.com>
# Updated by: Steve Micallef <steve@binarypool.com>
#    -> Inspired by https://github.com/combro2k/dockerfiles/tree/master/alpine-spiderfoot
# Updated by: Immanuel George <ikp4success@yahoo.com>
#
# Usage:
#
#   sudo docker build -t spiderfoot .
#   sudo docker run -it -p 5001:5001 spiderfoot

# Pull the base image.
FROM alpine:latest
WORKDIR /home/spiderfoot
COPY . .
ENV SPIDERFOOT_VERSION 3.0.0

# Run everything as one command so that only one layer is created
RUN apk --update add --no-cache --virtual build-dependencies gcc git curl py2-pip swig \
        tinyxml-dev python2-dev musl-dev openssl-dev libxslt-dev \
    && apk --update --no-cache add python2 musl openssl libxslt tinyxml \
    && pip --no-cache-dir install wheel \
    && pip --no-cache-dir install -r requirements.txt \
    && addgroup spiderfoot \
    && adduser -G spiderfoot -h /home/spiderfoot -s /sbin/nologin \
               -g "SpiderFoot User" -D spiderfoot \
    && cd /home \
    && chown -R spiderfoot:spiderfoot /home/spiderfoot \
    && apk del --purge build-dependencies \
    && rm -rf /var/cache/apk/* \
    && rm -rf /root/.cache

USER spiderfoot

EXPOSE 5001

# Run the application.
CMD ["/usr/bin/python", "./sf.py", "0.0.0.0:5001"]
