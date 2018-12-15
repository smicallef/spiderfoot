# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import division
from future import standard_library
standard_library.install_aliases()
from builtins import *
import re
import sys
import os
import subprocess
import socket
from .parser import WhoisEntry
from .whois import NICClient



def whois(url, command=False):
    # clean domain to expose netloc
    ip_match = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", url)
    if ip_match:
        domain = url
        try:
            result = socket.gethostbyaddr(url)
        except socket.herror as e:
            pass
        else:
            domain = extract_domain(result[0])
    else:
        domain = extract_domain(url)
    if command:
        # try native whois command
        r = subprocess.Popen(['whois', domain], stdout=subprocess.PIPE)
        text = r.stdout.read().decode()
    else:
        # try builtin client
        nic_client = NICClient()
        text = nic_client.whois_lookup(None, domain.encode('idna'), 0)
    return WhoisEntry.load(domain, text)


suffixes = None
def extract_domain(url):
    """Extract the domain from the given URL

    >>> print(extract_domain('http://www.google.com.au/tos.html'))
    google.com.au
    >>> print(extract_domain('abc.def.com'))
    def.com
    >>> print(extract_domain(u'www.公司.hk'))
    公司.hk
    >>> print(extract_domain('chambagri.fr'))
    chambagri.fr
    >>> print(extract_domain('www.webscraping.com'))
    webscraping.com
    >>> print(extract_domain('198.252.206.140'))
    stackoverflow.com
    >>> print(extract_domain('102.112.2O7.net'))
    2o7.net
    >>> print(extract_domain('globoesporte.globo.com'))
    globo.com
    >>> print(extract_domain('1-0-1-1-1-0-1-1-1-1-1-1-1-.0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0-0-0-0.info'))
    0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0-0-0-0.info
    """
    if re.match(r'\d+\.\d+\.\d+\.\d+', url):
        # this is an IP address
        return socket.gethostbyaddr(url)[0]

    # load known TLD suffixes
    global suffixes
    if not suffixes:
        # downloaded from https://publicsuffix.org/list/public_suffix_list.dat
        tlds_path = os.path.join(os.getcwd(), os.path.dirname(__file__), 'data', 'public_suffix_list.dat')
        with open(tlds_path, encoding='utf-8') as tlds_fp:
            suffixes = set(line.encode('utf-8') for line in tlds_fp.read().splitlines() if line and not line.startswith('//'))

    if not isinstance(url, str):
        url = url.decode('utf-8')
    url = re.sub('^.*://', '', url)
    url = url.split('/')[0].lower()

    # find the longest suffix match
    domain = b''
    for section in reversed(url.split('.')):
        if domain:
            domain = b'.' + domain
        domain = section.encode('utf-8') + domain
        if domain not in suffixes:
            break
    return domain.decode('utf-8')


if __name__ == '__main__':
    try:
        url = sys.argv[1]
    except IndexError:
        print('Usage: %s url' % sys.argv[0])
    else:
        print(whois(url))
