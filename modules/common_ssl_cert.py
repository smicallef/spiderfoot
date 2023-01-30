from spiderfoot import SpiderFootEvent

def process_ssl_cert_events(spiderfoot_plugin, cert, root_event):
    eventName = root_event.eventType
    
    if cert.get('issued'):
            new_event = SpiderFootEvent('SSL_CERTIFICATE_ISSUED', cert['issued'], spiderfoot_plugin.__name__, root_event)
            spiderfoot_plugin.notifyListeners(new_event)

    if cert.get('issuer'):
            new_event = SpiderFootEvent('SSL_CERTIFICATE_ISSUER', cert['issuer'], spiderfoot_plugin.__name__, root_event)
            spiderfoot_plugin.notifyListeners(new_event)

    if eventName != "IP_ADDRESS" and cert.get('mismatch'):
            new_event = SpiderFootEvent('SSL_CERTIFICATE_MISMATCH', ', '.join(cert.get('hosts')), spiderfoot_plugin.__name__, root_event)
            spiderfoot_plugin.notifyListeners(new_event)

    for san in set(cert.get('altnames', list())):
            domain = san.replace("*.", "")

            if spiderfoot_plugin.getTarget().matches(domain, includeChildren=True):
                    new_event_type = 'INTERNET_NAME'
                    if spiderfoot_plugin.opts['verify'] and not spiderfoot_plugin.sf.resolveHost(domain) and not spiderfoot_plugin.sf.resolveHost6(domain):
                            spiderfoot_plugin.debug(f"Host {domain} could not be resolved")
                            new_event_type += '_UNRESOLVED'
            else:
                    new_event_type = 'CO_HOSTED_SITE'

            new_event = SpiderFootEvent(new_event_type, domain, spiderfoot_plugin.__name__, root_event)
            spiderfoot_plugin.notifyListeners(new_event)

            if spiderfoot_plugin.sf.isDomain(domain, spiderfoot_plugin.opts['_internettlds']):
                    if new_event_type == 'CO_HOSTED_SITE':
                            new_event = SpiderFootEvent('CO_HOSTED_SITE_DOMAIN', domain, spiderfoot_plugin.__name__, root_event)
                            spiderfoot_plugin.notifyListeners(new_event)
                    else:
                            new_event = SpiderFootEvent('DOMAIN_NAME', domain, spiderfoot_plugin.__name__, root_event)
                            spiderfoot_plugin.notifyListeners(new_event)

    if cert.get('expired'):
            new_event = SpiderFootEvent("SSL_CERTIFICATE_EXPIRED", cert.get('expirystr', 'Unknown'), spiderfoot_plugin.__name__, root_event)
            spiderfoot_plugin.notifyListeners(new_event)
            return

    if cert.get('expiring'):
            new_event = SpiderFootEvent("SSL_CERTIFICATE_EXPIRING", cert.get('expirystr', 'Unknown'), spiderfoot_plugin.__name__, root_event)
            spiderfoot_plugin.notifyListeners(new_event)