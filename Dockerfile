#
# Spiderfoot Dockerfile
#
# http://www.spiderfoot.net
#
# Written by: Michael Pellon <m@pellon.io>
# Updated by: Chandrapal <bnchandrapal@protonmail.com>
# Updated by: Steve Micallef <steve@binarypool.com>
# Updated by: Steve Bate <svc-spiderfoot@stevebate.net>
#    -> Inspired by https://github.com/combro2k/dockerfiles/tree/master/alpine-spiderfoot
# Updated by: TheTechromancer
#
# Usage:
#
#   sudo docker build -t spiderfoot .
#   sudo docker run -p 5001:5001 --security-opt no-new-privileges spiderfoot
#
# Using Docker volume for spiderfoot data
#
#   sudo docker run -p 5001:5001 -v /mydir/spiderfoot:/var/lib/spiderfoot spiderfoot
#
# Using SpiderFoot remote command line with web server
#
#   docker run --rm -it spiderfoot sfcli.py -s http://my.spiderfoot.host:5001/
#
# Running spiderfoot commands without web server (can optionally specify volume)
#
#   sudo docker run --rm spiderfoot sf.py -h
#
# Running a shell in the container for maintenance
#   sudo docker run -it --entrypoint /bin/sh spiderfoot
#
# Running spiderfoot unit tests in container
#
#   sudo docker build -t spiderfoot-test --build-arg REQUIREMENTS=test/requirements.txt .
#   sudo docker run --rm spiderfoot-test -m pytest --flake8 .

FROM python:3

# Install dependencies in a single layer
# RUN apt-get -y update && apt-get -y install nmap

RUN groupadd spiderfoot \
    && useradd -m -g spiderfoot -d /home/spiderfoot -s /sbin/nologin \
    -c "SpiderFoot User" spiderfoot

ENV SPIDERFOOT_LOGS /home/spiderfoot/log
ENV SPIDERFOOT_DATA /var/lib/spiderfoot
RUN mkdir -p  "$SPIDERFOOT_LOGS" "$SPIDERFOOT_DATA" \
   && chown spiderfoot:spiderfoot "$SPIDERFOOT_LOGS" "$SPIDERFOOT_DATA"

COPY . .

USER spiderfoot

WORKDIR /home/spiderfoot

ENV VIRTUAL_ENV=/home/spiderfoot/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN mkdir -p "$VIRTUAL_ENV" || true
ARG REQUIREMENTS=requirements.txt
COPY "$REQUIREMENTS" requirements.txt
RUN python -m venv "$VIRTUAL_ENV"
RUN pip install -U pip
RUN pip install -r "$REQUIREMENTS"

EXPOSE 5001

# Run the application.
CMD ["sf.py", "-l", "0.0.0.0:5001"]
