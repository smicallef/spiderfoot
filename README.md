# llamaFoot

llamaFoot is a fork of [SpiderFoot](https://github.com/smicallef/spiderfoot) by Steve Micallef. It keeps the SpiderFoot scan engine and correlation rules, and changes three things:

1. **Free sources only.** Every module that depends on a paid or tiered API has been removed (77 modules, including Shodan, VirusTotal, SecurityTrails, Censys, HaveIBeenPwned and Hunter). What remains is internal modules, external tools and free sources. A few of those want a free key, and they stay switched off until you add one.
2. **One search box.** Type anything and llamaFoot works out what it is, then runs the modules that apply to it. No target type to pick and no quotes to remember.
3. **AI analyst.** After a scan, an AI engine of your choice writes a summary, ranks the findings, flags risks and suggests what to look at next. You can keep it fully local, or use a free cloud tier.

SpiderFoot is MIT licensed and so is this fork. See `LICENSE`.

## What you can search for

| You type | Detected as | Notes |
|---|---|---|
| `example.com` | Domain Name | Uses the public suffix list, so `example.co.uk` is a domain and `www.example.co.uk` is a host |
| `abc.example.com` | Hostname/Sub-domain | URLs work too: the host is extracted |
| `1.2.3.4` | IPv4 Address | `1.2.3.4:8080` is accepted and the port is ignored |
| `2606:4700:4700::1111` | IPv6 Address | `[::1]` and zone ids are handled |
| `1.2.3.0/24`, `2606:4700::/32` | Subnet | Host bits are cleared, with a note |
| `AS13335` or `13335` | Network ASN | |
| `bob@example.com` | E-mail address | `mailto:` and `Name <bob@example.com>` work |
| `+12345678901` | Phone Number | Normalised to E.164. Needs a country code |
| `1HesYJSP1QqcyPEjnQ9vzBL1wujruNGe7R` | Bitcoin Address | Checksum is verified |
| `John Smith` | Human Name | Quotes optional |
| `jsmith2000` or `@jsmith2000` | Username | Quotes optional |

Quotes always win: `"example.com"` is searched as a username and `"John Smith"` as a name.

Where an input could mean more than one thing, llamaFoot shows its best guess with a confidence level and lists the alternatives (for example, a long run of digits that is a valid ASN and also a valid phone number). The web UI shows what it detected as you type, and the CLI prints it before the scan starts.

## Scan modes

* **Smart** (default). Runs the modules that work on what you typed, plus the modules that can use what those find, two steps out. Slow, intrusive and external-tool modules are skipped, and so are modules whose API key you have not set.
* **Smart + deep.** Follows every pivot to the end and includes the slow and external-tool modules. Touches the target directly.
* **All / Footprint / Investigate / Passive.** The original SpiderFoot use cases.

## AI engines

Pick one on the new scan page, or on a scan's **AI Summary** button. Each engine shows whether it is local or a free cloud tier, and a tooltip with its setup steps.

| Engine | Where it runs | Needs |
|---|---|---|
| Ollama (local) | Your server. Nothing leaves it | [Ollama](https://ollama.com/download) installed and a pulled model |
| Ollama Cloud | Ollama's servers | Free account and an API key from ollama.com/settings/keys |
| Groq | Groq's servers | Free API key |
| OpenRouter (free models) | The model host's servers | Free API key. Pick models ending in `:free` |
| Google Gemini | Google's servers | Free API key from Google AI Studio |

Free tiers, included models and rate limits are set by each provider and change over time. Cloud engines receive a digest of your scan results, so use a local model for sensitive investigations. Large local models are slow without a GPU.

Configuration can be done in the UI, or on the server with environment variables:

| Variable | Purpose |
|---|---|
| `OLLAMA_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY` | API keys. Environment variables take priority over saved keys |
| `LLAMAFOOT_LLM_PROVIDER`, `LLAMAFOOT_LLM_MODEL` | Default engine and model |
| `LLAMAFOOT_OLLAMA_HOST` | Local Ollama address, default `http://127.0.0.1:11434` |
| `LLAMAFOOT_LLM_READONLY=1` | Lock AI settings so they cannot be changed from the web UI |

Keys saved from the UI are written to `llamafoot_llm.json` in the SpiderFoot data directory with `0600` permissions and are never sent back to the browser.

### How the AI is kept honest

Scan data comes from the open internet, so it can contain text written to manipulate an AI. llamaFoot sends the model a bounded digest wrapped in delimiters, tells it to treat that content strictly as data, strips control characters and delimiter look-alikes, and shows the answer as plain text. The AI cannot start scans, change settings or call tools. It can still be wrong, so check its findings against the raw results.

## Install and run

Python 3.9 or newer (developed and tested on 3.13).

```
git clone https://github.com/MohdJuma/llamaFoot.git
cd llamaFoot
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
python3 ./sf.py -l 127.0.0.1:5001
```

Then open http://127.0.0.1:5001.

Command line:

```
python3 ./sf.py -s example.com            # target type is detected for you
python3 ./sf.py -s "John Smith" -u all
python3 ./sf.py -s AS13335 -m sfp_bgpview,sfp_ripe
```

Running it for other people to use? Put it behind authentication and TLS (see the SpiderFoot docs on `passwd` and `generate-certificate`), set `LLAMAFOOT_LLM_READONLY=1`, and supply keys through environment variables. Scans make requests to the target and to third party sources from your server's address.

## Modules that need a free key

Eleven remaining modules can use a free key. They are skipped by Smart mode until a key is set in Settings. Everything else works without any account.

## Use responsibly

llamaFoot collects publicly available information. Searching for people, usernames and phone numbers can intrude on privacy. Only investigate targets you own, are authorised to assess, or have a lawful reason to research, and follow the laws and platform terms that apply to you.

## Credits

Built on [SpiderFoot](https://github.com/smicallef/spiderfoot) by Steve Micallef and its contributors. See `THANKYOU` for the full list.
