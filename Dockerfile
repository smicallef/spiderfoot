#
# Spiderfoot Dockerfile
#
# http://www.spiderfoot.net
#
# Written originally by: Michael Pellon <m@pellon.io>
# Further optimized by António Meireles <antonio.meireles@reformi.st>
#
# Usage:
#
#   sudo docker build -t spiderfoot .
#   sudo docker run -it -p 8080:8080 spiderfoot

# Pull the base image.
FROM ubuntu:latest

ENV VERSION 2.6.1
ENV RELEASE ${VERSION}-final
ENV TARBALL https://github.com/smicallef/spiderfoot/archive/v${RELEASE}.tar.gz

ENV DEBIAN_FRONTEND noninteractive
ENV TERM linux

EXPOSE 8080

# Install pre-requisites.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl git python-pip python-lxml python-m2crypto python-netaddr \
        python-mako python-lxml && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
# as ubuntu's 'native' cherrypy not up to the task
RUN pip install cherrypy

# Create a dedicated/non-privileged user to run the app.
RUN addgroup spiderfoot && \
    useradd -r -g spiderfoot -d /home/spiderfoot -s /sbin/nologin \
        -c "SpiderFoot User" spiderfoot

# Download the specified release.
WORKDIR /home
RUN curl -sSL ${TARBALL} | tar -v -C /home -xz && \
    mv /home/spiderfoot-${RELEASE} /home/spiderfoot && \
    chown -R spiderfoot:spiderfoot /home/spiderfoot

USER spiderfoot
WORKDIR /home/spiderfoot

# Run the application.
ENTRYPOINT ["/usr/bin/python"]
CMD ["sf.py", "0.0.0.0:8080"]
