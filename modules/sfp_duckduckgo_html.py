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
        "summary": "Discover links for a domain or phone number using DuckDuckGo HTML results.",
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
        return ["INTERNET_NAME", "PHONE_NUMBER"]

    def producedEvents(self):
        return ["LINKED_URL_INTERNAL", "LINKED_URL_EXTERNAL"]

    def handleEvent(self, event):
        target = self.getTarget()
        if target.targetType not in ("INTERNET_NAME", "PHONE_NUMBER"):
            return
        target_value = target.targetValue.rstrip(".").lower()
        if event.data.rstrip(".").lower() != target_value or target_value in self.results:
            return
        self.results[target_value] = True
        is_domain = target.targetType == "INTERNET_NAME"
        query = urlencode({"q": "site:" + target_value if is_domain else '"' + target_value + '"'})
        response = self.sf.fetchUrl(
            "https://html.duckduckgo.com/html/?" + query,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts["_useragent"],
        )
        if not response:
            self.error("DuckDuckGo HTML no devolvió respuesta; revisa la conexión.")
            return
        code = str(response.get("code") or "desconocido")
        if code != "200":
            self.error(f"DuckDuckGo HTML respondió con HTTP {code}; no se procesaron resultados.")
            return
        if not response.get("content"):
            self.error("DuckDuckGo HTML respondió con HTTP 200 pero sin contenido.")
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
            internal = is_domain and (result_host == target_value or result_host.endswith("." + target_value))
            kind = "LINKED_URL_INTERNAL" if internal else "LINKED_URL_EXTERNAL"
            self.notifyListeners(SpiderFootEvent(kind, url, self.__name__, event))
            if len(emitted) >= max(1, int(self.opts["max_results"])):
                break
        self.info(f"DuckDuckGo HTML: {len(emitted)} enlaces emitidos para {target_value}.")
