# -*- coding: utf-8 -*-
from __future__ import absolute_import
import re
from collections import defaultdict
from functools import partial
from adblockparser.utils import split_data


class AdblockRule(object):
    r"""
    AdBlock Plus rule.

    Check these links for the format details:

    * https://adblockplus.org/en/filter-cheatsheet
    * https://adblockplus.org/en/filters

    Instantiate AdblockRule with a rule line:

    >>> from adblockparser import AdblockRule
    >>> rule = AdblockRule("@@||mydomain.no/artikler/$~third-party")

    Parsed data is available as rule attributes:

    >>> rule.is_comment
    False
    >>> rule.is_exception
    True
    >>> rule.is_html_rule
    False
    >>> rule.options
    {'third-party': False}
    >>> print(rule.regex)
    ^(?:[^:/?#]+:)?(?://(?:[^/?#]*\.)?)?mydomain\.no/artikler/

    To check if rule applies to an URL, use ``match_url`` method::

    >>> rule = AdblockRule("swf|")
    >>> rule.match_url("http://example.com/annoyingflash.swf")
    True
    >>> rule.match_url("http://example.com/swf/index.html")
    False

    Rules involving CSS selectors are detected but not supported well
    (``match_url`` doesn't work for them):

    >>> AdblockRule("domain.co.uk,domain2.com#@#.ad_description").is_html_rule
    True
    >>> AdblockRule("##.spot-ad").is_html_rule
    True
    """

    BINARY_OPTIONS = [
        "script",
        "image",
        "stylesheet",
        "object",
        "xmlhttprequest",
        "object-subrequest",
        "subdocument",
        "document",
        "elemhide",
        "other",
        "background",
        "xbl",
        "ping",
        "dtd",
        "media",
        "third-party",
        "match-case",
        "collapse",
        "donottrack",
    ]
    OPTIONS_SPLIT_PAT = ',(?=~?(?:%s))' % ('|'.join(BINARY_OPTIONS + ["domain"]))
    OPTIONS_SPLIT_RE = re.compile(OPTIONS_SPLIT_PAT)

    __slots__ = ['raw_rule_text', 'is_comment', 'is_html_rule', 'is_exception',
                 'raw_options', 'options', '_options_keys', 'rule_text',
                 'regex']

    def __init__(self, rule_text):
        self.raw_rule_text = rule_text

        rule_text = rule_text.strip()
        self.is_comment = rule_text.startswith(('!', '[Adblock'))
        if self.is_comment:
            self.is_html_rule = self.is_exception = False
        else:
            self.is_html_rule = '##' in rule_text or '#@#' in rule_text  # or rule_text.startswith('#')
            self.is_exception = rule_text.startswith('@@')
            if self.is_exception:
                rule_text = rule_text[2:]

        if not self.is_comment and '$' in rule_text:
            rule_text, options_text = rule_text.split('$', 1)
            self.raw_options = self._split_options(options_text)
            self.options = dict(self._parse_option(opt) for opt in self.raw_options)
        else:
            self.raw_options = []
            self.options = {}
        self._options_keys = frozenset(self.options.keys()) - set(['match-case'])

        self.rule_text = rule_text

        if self.is_comment or self.is_html_rule:
            # TODO: add support for HTML rules.
            # We should split the rule into URL and HTML parts,
            # convert URL part to a regex and parse the HTML part.
            self.regex = ''
        else:
            self.regex = self.rule_to_regex(rule_text)

    def match_url(self, url, options=None):
        """
        Return if this rule matches the URL.

        What to do if rule is matched is up to developer. Most likely
        ``.is_exception`` attribute should be taken in account.
        """
        options = options or {}
        for optname in self.options:
            if optname == 'match-case':  # TODO
                continue

            if optname not in options:
                raise ValueError("Rule requires option %s" % optname)

            if optname == 'domain':
                if not self._domain_matches(options['domain']):
                    return False
                continue

            if options[optname] != self.options[optname]:
                return False

        return self._url_matches(url)

    def _domain_matches(self, domain):
        domain_rules = self.options['domain']
        for domain in _domain_variants(domain):
            if domain in domain_rules:
                return domain_rules[domain]
        return False

    def _url_matches(self, url):
        return bool(re.search(self.regex, url))

    def matching_supported(self, options=None):
        """
        Return whether this rule can return meaningful result,
        given the `options` dict. If some options are missing,
        then rule shouldn't be matched against, and this function
        returns False.

        >>> rule = AdblockRule("swf|")
        >>> rule.matching_supported({})
        True
        >>> rule = AdblockRule("swf|$third-party")
        >>> rule.matching_supported({})
        False
        >>> rule.matching_supported({'domain': 'example.com', 'third-party': False})
        True

        """
        if self.is_comment:
            return False

        if self.is_html_rule:  # HTML rules are not supported yet
            return False

        options = options or {}
        keys = set(options.keys())
        if not keys.issuperset(self._options_keys):
            # some of the required options are not given
            return False

        return True

    @classmethod
    def _split_options(cls, options_text):
        return cls.OPTIONS_SPLIT_RE.split(options_text)

    @classmethod
    def _parse_domain_option(cls, text):
        domains = text[len('domain='):]
        parts = domains.replace(',', '|').split('|')
        return dict(cls._parse_option_negation(p) for p in parts)

    @classmethod
    def _parse_option_negation(cls, text):
        return (text.lstrip('~'), not text.startswith('~'))

    @classmethod
    def _parse_option(cls, text):
        if text.startswith("domain="):
            return ("domain", cls._parse_domain_option(text))
        return cls._parse_option_negation(text)

    @classmethod
    def rule_to_regex(cls, rule):
        """
        Convert AdBlock rule to a regular expression.
        """
        if not rule:
            raise ValueError("Invalid rule")
            # return rule

        # escape special regex characters
        rule = re.sub(r"([.$+?{}()\[\]\\])", r"\\\1", rule)

        # XXX: the resulting regex must use non-capturing groups (?:
        # for performance reasons; also, there is a limit on number
        # of capturing groups, no using them would prevent building
        # a single regex out of several rules.

        # Separator character ^ matches anything but a letter, a digit, or
        # one of the following: _ - . %. The end of the address is also
        # accepted as separator.
        rule = rule.replace("^", "(?:[^\w\d_\-.%]|$)")

        # * symbol
        rule = rule.replace("*", ".*")

        # | in the end means the end of the address
        if rule[-1] == '|':
            rule = rule[:-1] + '$'

        # || in the beginning means beginning of the domain name
        if rule[:2] == '||':
            # XXX: it is better to use urlparse for such things,
            # but urlparse doesn't give us a single regex.
            # Regex is based on http://tools.ietf.org/html/rfc3986#appendix-B
            if len(rule) > 2:
                #          |            | complete part     |
                #          |  scheme    | of the domain     |
                rule = r"^(?:[^:/?#]+:)?(?://(?:[^/?#]*\.)?)?" + rule[2:]

        elif rule[0] == '|':
            # | in the beginning means start of the address
            rule = '^' + rule[1:]

        # other | symbols should be escaped
        # we have "|$" in our regexp - do not touch it
        rule = re.sub("(\|)[^$]", r"\|", rule)

        return rule

    def __repr__(self):
        return "AdblockRule(%r)" % self.raw_rule_text


class AdblockRules(object):
    """
    AdblockRules is a class for checking URLs against multiple AdBlock rules.

    It is more efficient to use AdblockRules instead of creating AdblockRule
    instances manually and checking them one-by-one because AdblockRules
    optimizes some common cases.
    """

    def __init__(self, rules, supported_options=None, skip_unsupported_rules=True,
                 use_re2='auto', max_mem=256*1024*1024, rule_cls=AdblockRule):

        if supported_options is None:
            self.supported_options = rule_cls.BINARY_OPTIONS + ['domain']
        else:
            self.supported_options = supported_options

        self.uses_re2 = _is_re2_supported() if use_re2 == 'auto' else use_re2
        self.re2_max_mem = max_mem
        self.rule_cls = rule_cls
        self.skip_unsupported_rules = skip_unsupported_rules

        _params = dict((opt, True) for opt in self.supported_options)
        self.rules = [
            r for r in (self.rule_cls(r) for r in rules)
            if r.regex and r.matching_supported(_params)
        ]

        # "advanced" rules are rules with options,
        # "basic" rules are rules without options
        advanced_rules, basic_rules = split_data(self.rules, lambda r: r.options)

        # rules with domain option are handled separately:
        # we may discard most rules based on domain information,
        # so parser builds an index for that later.
        domain_rules, non_domain_rules = split_data(
            advanced_rules,
            lambda r: 'domain' in r.options
        )

        # split rules into blacklists and whitelists
        self.blacklist, self.whitelist = self._split_bw(basic_rules)
        _combined = partial(_combined_regex, use_re2=self.uses_re2, max_mem=max_mem)
        self.blacklist_re = _combined([r.regex for r in self.blacklist])
        self.whitelist_re = _combined([r.regex for r in self.whitelist])

        self.blacklist_adv, self.whitelist_adv = self._split_bw(non_domain_rules)
        self.blacklist_domains, self.whitelist_domains = self._split_bw_domain(domain_rules)


    def should_block(self, url, options=None):
        # TODO: group rules with similar options and match them in bigger steps
        options = options or {}
        if self._is_whitelisted(url, options):
            return False
        if self._is_blacklisted(url, options):
            return True
        return False

    def _is_whitelisted(self, url, options):
        return self._matches(
            url, options,
            self.whitelist_re, self.whitelist_domains, self.whitelist_adv
        )

    def _is_blacklisted(self, url, options):
        return self._matches(
            url, options,
            self.blacklist_re, self.blacklist_domains, self.blacklist_adv
        )

    def _matches(self, url, options,
                 general_re, rules_with_domains, rules_with_options):
        """
        Return if ``url``/``options`` are matched by rules defined by
        ``general_re``, ``rules_with_domains`` and ``rules_with_options``.

        ``general_re`` is a compiled regex for rules without options.

        ``rules_with_domains`` is a {domain: [rules]} mapping - per-domain
        index of applicable rules which have 'domain' option.

         ``rules_with_options`` is a list of AdblockRule instances that
        don't have 'domain' option, but have other options.
        """
        if general_re and general_re.search(url):
            return True

        rules = []
        if 'domain' in options and rules_with_domains:
            src_domain = options['domain']
            for domain in _domain_variants(src_domain):
                if domain in rules_with_domains:
                    rules = rules_with_domains[domain]
                    break

        rules.extend(rules_with_options)

        if self.skip_unsupported_rules:
            rules = [rule for rule in rules if rule.matching_supported(options)]

        return any(rule.match_url(url, options) for rule in rules)

    @classmethod
    def _split_bw(cls, rules):
        return split_data(rules, lambda r: not r.is_exception)

    @classmethod
    def _split_bw_domain(cls, rules):
        blacklist, whitelist = cls._split_bw(rules)
        return cls._domain_index(blacklist), cls._domain_index(whitelist)

    @classmethod
    def _domain_index(cls, rules):
        result = defaultdict(list)
        for rule in rules:
            for domain in rule.options.get('domain', []):
                result[domain].append(rule)
        return dict(result)


def _domain_variants(domain):
    """
    >>> list(_domain_variants("foo.bar.example.com"))
    ['foo.bar.example.com', 'bar.example.com', 'example.com']
    """
    parts = domain.split('.')
    for i in range(len(parts), 1, -1):
        yield ".".join(parts[-i:])


def _combined_regex(regexes, flags=re.IGNORECASE, use_re2=False, max_mem=None):
    """
    Return a compiled regex combined (using OR) from a list of ``regexes``.
    If there is nothing to combine, None is returned.

    re2 library (https://github.com/axiak/pyre2) often can match and compile
    large regexes much faster than stdlib re module (10x is not uncommon),
    but there are some gotchas:

    * at the moment of writing (Feb 2014) latest re2 pypi release (0.2.20)
      doesn't work; pyre2 must be installed from the github repo;
    * in case of "DFA out of memory" errors use ``max_mem`` argument
      to increase the amount of memory re2 is allowed to use.
    """
    joined_regexes = "|".join(r for r in regexes if r)
    if not joined_regexes:
        return None

    if use_re2:
        import re2
        return re2.compile(joined_regexes, flags=flags, max_mem=max_mem)
    return re.compile(joined_regexes, flags=flags)


def _is_re2_supported():
    try:
        import re2
    except ImportError:
        return False

    # re2.match doesn't work in re2 v0.2.20 installed from pypi
    # (it always returns None).
    return re2.match('foo', 'foo') is not None
