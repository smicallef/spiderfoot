"""Experimental DuckDuckGo HTML result discovery."""

from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class ResultParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        attrs = dict(attrs)
        if "result__a" in attrs.get("class", "").split() and attrs.get("href"):
            self.links.append(attrs["href"])


def result_url(link):
    url = urljoin("https://html.duckduckgo.com/", link)
    parsed = urlsplit(url)
    if parsed.hostname and parsed.hostname.lower() in ("duckduckgo.com", "html.duckduckgo.com"):
        url = parse_qs(parsed.query).get("uddg", [""])[0]
        parsed = urlsplit(url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    return url


class sfp_duckduckgo_html(SpiderFootPlugin):
    meta = {
        "name": "DuckDuckGo HTML (experimental)",
        "summary": "Discover links for the target using DuckDuckGo HTML results.",
        "flags": [],
        "useCases": [],
        "categories": ["Search Engines"],
    }
    opts = {"max_results": 20}
    optdescs = {"max_results": "Maximum number of result links to emit."}

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        for opt in userOpts:
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["INTERNET_NAME"]

    def producedEvents(self):
        return ["LINKED_URL_INTERNAL", "LINKED_URL_EXTERNAL"]

    def handleEvent(self, event):
        target = self.getTarget()
        if target.targetType != "INTERNET_NAME":
            return
        host = target.targetValue.rstrip(".").lower()
        if event.data.rstrip(".").lower() != host or host in self.results:
            return
        self.results[host] = True
        query = urlencode({"q": "site:" + host})
        response = self.sf.fetchUrl(
            "https://html.duckduckgo.com/html/?" + query,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts["_useragent"],
        )
        if not response or response.get("code") != "200" or not response.get("content"):
            self.error("DuckDuckGo HTML no respondió correctamente; puede haber un bloqueo o limitación.")
            return
        parser = ResultParser()
        parser.feed(response["content"])
        if not parser.links:
            self.info("DuckDuckGo HTML no devolvió enlaces reconocibles; puede no haber resultados o haber cambiado el formato.")
            return
        emitted = set()
        for link in parser.links:
            if self.checkForStop():
                break
            url = result_url(link)
            if not url or url in emitted:
                continue
            emitted.add(url)
            result_host = urlsplit(url).hostname.rstrip(".").lower()
            internal = result_host == host or result_host.endswith("." + host)
            kind = "LINKED_URL_INTERNAL" if internal else "LINKED_URL_EXTERNAL"
            self.notifyListeners(SpiderFootEvent(kind, url, self.__name__, event))
            if len(emitted) >= max(1, int(self.opts["max_results"])):
                break
        self.info(f"DuckDuckGo HTML: {len(emitted)} enlaces emitidos para {host}.")
