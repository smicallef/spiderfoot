#
# Spiderfoot Dockerfile
#
# http://www.spiderfoot.net
#
# Written by: Michael Pellon <m@pellon.io>
# Updated by: Chandrapal <bnchandrapal@protonmail.com>
# Updated by: Steve Micallef <steve@binarypool.com>
#    -> Inspired by https://github.com/combro2k/dockerfiles/tree/master/alpine-spiderfoot
#
# Usage:
#
#   sudo docker build -t spiderfoot .
#   sudo docker run -it -p 5001:5001 spiderfoot

# Pull the base image.
FROM alpine:latest
COPY requirements.txt .

# Run everything as one command so that only one layer is created
RUN apk --update add --no-cache --virtual build-dependencies gcc git curl py3-pip swig \
        tinyxml-dev python3-dev musl-dev openssl-dev libffi-dev libxslt-dev \
    && apk --update --no-cache add python3 musl openssl libxslt tinyxml jpeg-dev openjpeg-dev zlib-dev \
    && pip3 --no-cache-dir install wheel \
    && pip3 --no-cache-dir install -r requirements.txt \
    && addgroup spiderfoot \
    && adduser -G spiderfoot -h /home/spiderfoot -s /sbin/nologin \
               -g "SpiderFoot User" -D spiderfoot \
    && rmdir /home/spiderfoot \
    && cd /home \
    && curl -sSL https://github.com/smicallef/spiderfoot/archive/py3.tar.gz \
       | tar -v -C /home -xz \
    && mv /home/spiderfoot-py3 /home/spiderfoot \
    && chown -R spiderfoot:spiderfoot /home/spiderfoot \
    && apk del --purge build-dependencies \
    && rm -rf /var/cache/apk/* \
    && rm -rf /root/.cache

USER spiderfoot
WORKDIR /home/spiderfoot

EXPOSE 5001

# Run the application.
ENTRYPOINT ["/usr/bin/python3"] 
CMD ["./sf.py", "-l", "0.0.0.0:5001"]
