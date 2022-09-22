#
# Spiderfoot Dockerfile (Full - includes all CLI tools, etc.)
#
# http://www.spiderfoot.net
#
# Written by: TheTechromancer
#

FROM python:3

# Install tools/dependencies from apt
RUN apt-get -y update && apt-get -y install nbtscan onesixtyone nmap

# Compile other tools from source
RUN mkdir /tools || true
WORKDIR /tools

# Install Golang tools
RUN apt-get -y update && apt-get -y install golang
ENV GOPATH="/go"
ENV PATH="$GOPATH/bin:$PATH"
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin"

# Install Ruby tools for WhatWeb
RUN apt-get -y update && apt-get -y install ruby ruby-dev bundler
# Install WhatWeb
RUN git clone https://github.com/urbanadventurer/WhatWeb \
    && gem install rchardet mongo json && cd /tools/WhatWeb \
    && bundle install && cd /tools

RUN groupadd spiderfoot \
    && useradd -m -g spiderfoot -d /home/spiderfoot -s /sbin/nologin \
    -c "SpiderFoot User" spiderfoot

# Install RetireJS
RUN apt remove -y cmdtest \
    && apt remove -y yarn \
    && curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add - \
    && echo 'deb https://dl.yarnpkg.com/debian/ stable main' |tee /etc/apt/sources.list.d/yarn.list \
    && apt-get update \
    && apt-get install yarn -y \
    && yarn install \
    && curl -fsSL https://deb.nodesource.com/setup_17.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g retire

# Install Google Chrome the New Way (Not via apt-key)
RUN wget -qO - https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/googlechrome-linux-keyring.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/googlechrome-linux-keyring.gpg] http://dl.google.com/linux/chrome/deb/ stable main" | tee /etc/apt/sources.list.d/google-chrome.list \
    && apt -y update && apt install --allow-unauthenticated -y google-chrome-stable

# Install Wappalyzer
RUN git clone https://github.com/AliasIO/wappalyzer.git \
    && cd wappalyzer \
    && yarn install && yarn run link

# Install Nuclei
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v2.6.5/nuclei_2.6.5_linux_amd64.zip \
    && unzip nuclei_2.6.5_linux_amd64.zip \
    && git clone https://github.com/projectdiscovery/nuclei-templates.git

# Install testssl.sh
RUN apt-get install -y bsdmainutils dnsutils coreutils
RUN git clone https://github.com/drwetter/testssl.sh.git

# Install Snallygaster and TruffleHog
RUN pip3 install snallygaster trufflehog

# Place database and logs outside installation directory
ENV SPIDERFOOT_DATA /var/lib/spiderfoot
ENV SPIDERFOOT_LOGS /var/lib/spiderfoot/log
ENV SPIDERFOOT_CACHE /var/lib/spiderfoot/cache

RUN mkdir -p $SPIDERFOOT_DATA || true \
    && mkdir -p $SPIDERFOOT_LOGS || true \
    && mkdir -p $SPIDERFOOT_CACHE || true \
    && chown spiderfoot:spiderfoot $SPIDERFOOT_DATA \
    && chown spiderfoot:spiderfoot $SPIDERFOOT_LOGS \
    && chown spiderfoot:spiderfoot $SPIDERFOOT_CACHE

WORKDIR /home/spiderfoot
COPY . .

ENV VIRTUAL_ENV=/opt/venv
RUN mkdir -p "$VIRTUAL_ENV" || true
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN python -m venv "$VIRTUAL_ENV"

ARG REQUIREMENTS=requirements.txt
COPY "$REQUIREMENTS" requirements.txt

RUN chown -R spiderfoot:spiderfoot /tools
RUN chown -R spiderfoot:spiderfoot "$VIRTUAL_ENV"
RUN chown -R spiderfoot:spiderfoot "/home/spiderfoot"

USER spiderfoot

RUN pip install -U pip
RUN pip install -r "$REQUIREMENTS"

# Install Python tools
RUN pip install dnstwist
# CMSeeK
WORKDIR /tools
RUN git clone https://github.com/Tuhinshubhra/CMSeeK && cd CMSeeK \
    && pip install -r requirements.txt && mkdir Results

# Install wafw00f
RUN git clone https://github.com/EnableSecurity/wafw00f \
    && cd wafw00f \
    && python3 setup.py install
WORKDIR /home/spiderfoot

EXPOSE 5001

# Run the application
CMD python -c 'from spiderfoot import SpiderFootDb; \
db = SpiderFootDb({"__database": "/var/lib/spiderfoot/spiderfoot.db"}); \
db.configSet({ \
    "sfp_tool_dnstwist:dnstwistpath": "/opt/venv/bin/dnstwist", \
    "sfp_tool_cmseek:cmseekpath": "/tools/CMSeeK/cmseek.py", \
    "sfp_tool_whatweb:whatweb_path": "/tools/WhatWeb/whatweb", \
    "sfp_tool_wafw00f:wafw00f_path": "/opt/venv/bin/wafw00f", \
    "sfp_tool_onesixtyone:onesixtyone_path": "/usr/bin/onesixtyone", \
    "sfp_tool_retirejs:retirejs_path": "/usr/bin/retire", \
    "sfp_tool_testsslsh:testsslsh_path": "/tools/testssl.sh/testssl.sh", \
    "sfp_tool_snallygaster:snallygaster_path": "/usr/local/bin/snallygaster", \
    "sfp_tool_trufflehog:trufflehog_path": "/usr/local/bin/trufflehog", \
    "sfp_tool_nuclei:nuclei_path": "/tools/nuclei", \
    "sfp_tool_nuclei:template_path": "/tools/nuclei-templates", \
    "sfp_tool_wappalyzer:wappalyzer_path": "/tools/wappalyzer/src/drivers/npm/cli.js", \
    "sfp_tool_nbtscan:nbtscan_path": "/usr/bin/nbtscan", \
    "sfp_tool_nmap:nmappath": "DISABLED_BECAUSE_NMAP_REQUIRES_ROOT_TO_WORK" \
})' || true && ./sf.py -l 0.0.0.0:5001
