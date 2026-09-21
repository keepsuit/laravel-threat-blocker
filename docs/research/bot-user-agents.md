# Bot User-Agent research for issue #11

## Findings

### 1. Conservative non-browser candidate set

These signatures identify common programmatic HTTP stacks rather than a browser. They are reasonable candidates for a detector concerned with automated form submissions, but matching should be case-insensitive and substring-based: callers can append application identifiers, change casing, or override the header.

| Exact fragment/pattern | Evidence and rationale |
| --- | --- |
| `python-requests/` | Requests’ official source constructs the default as `python-requests/{version}`: [psf/requests `utils.py`](https://github.com/psf/requests/blob/main/src/requests/utils.py). Requests is a general HTTP client and exposes request data/body APIs, so this is a high-signal non-browser marker, not proof of abuse. |
| `python-httpx/` | HTTPX’s official source sets `USER_AGENT = f"python-httpx/{__version__}"` and installs it in client defaults: [HTTPX `_client.py`](https://github.com/encode/httpx/blob/master/httpx/_client.py). HTTPX supports sync/async requests and form/file content, making it relevant to automated submissions. |
| `Python-urllib/` | CPython’s official `urllib.request` source builds `Python-urllib/{version}`: [CPython `urllib/request.py`](https://github.com/python/cpython/blob/main/Lib/urllib/request.py). The official docs also describe passing `data` to `urlopen` and the default form content type: [urllib.request documentation](https://github.com/python/cpython/blob/main/Doc/library/urllib.request.rst). |
| `Go-http-client/1.1` | Go’s standard library defines this exact default and says `Request.Write` uses it when no User-Agent is supplied: [Go `net/http/request.go`](https://github.com/golang/go/blob/master/src/net/http/request.go). It is a useful stable marker for Go automation. |
| `curl/` | curl’s official scripting guide says its default is `User-Agent: curl/{VERSION}` and documents POST with `--data`/`--form`: [curl HTTP scripting](https://curl.se/docs/httpscripting.html). |
| `Wget/` | GNU Wget’s official manual says it normally identifies as `Wget/{version}` and supports `--post-data`/`--post-file`: [GNU Wget manual](https://www.gnu.org/software/wget/manual/wget.html). |
| `GuzzleHttp/` | Guzzle’s official source returns `GuzzleHttp/{major}` as its default User-Agent: [Guzzle `Utils.php`](https://github.com/guzzle/guzzle/blob/8.0/src/Utils.php). Guzzle’s official README documents POST, multipart uploads, cookies, and request bodies: [Guzzle README](https://github.com/guzzle/guzzle/blob/8.0/README.md). Match the prefix, not only `/7` or `/8`, to cover supported majors. |
| `axios/` | Axios’s official Node HTTP adapter sets `User-Agent` to `axios/{VERSION}`: [Axios `http.js`](https://github.com/axios/axios/blob/v1.x/lib/adapters/http.js). This is a strong Node-client marker when the Node adapter is used; browser/fetch adapters may expose a browser or no custom UA. |
| `Mechanize/` | Ruby Mechanize’s official source defines the default as `Mechanize/{version} Ruby/{version} (...)`; its official README explicitly describes HTML form filling and `submit`: [Mechanize source](https://github.com/sparklemotion/mechanize/blob/main/lib/mechanize.rb), [Mechanize README](https://github.com/sparklemotion/mechanize). This is the strongest direct form-automation candidate. |
| `HTTPie/` | HTTPie’s official repository documents the default `User-Agent: HTTPie/<version>` for its CLI HTTP client: [HTTPie repository](https://github.com/jdx/httpie). It is useful as an optional addition for CLI-driven submissions. |

Recommended default: start with the first nine fragments, and add `HTTPie/` only if issue #11’s observed traffic includes CLI clients. Do not anchor to the complete UA or version; the owning projects document versioned strings and allow overrides.

### 2. Legitimate crawlers and link-preview fetchers: do not put in conservative defaults

- `Googlebot` (including `Googlebot/2.1`), `Googlebot-Image/1.0`, `Googlebot-Video/1.0`, `Storebot-Google/1.0`, `Google-InspectionTool/1.0`, and `GoogleOther` are documented Google crawlers/fetchers. Google says they serve Search, Shopping, testing, or other product functions, and warns that blocking Googlebot affects Search features: [Google common crawlers](https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers), [What Is Googlebot](https://developers.google.com/search/docs/crawling-indexing/googlebot). Exclude these from a form-bot default; use robots/rate controls or explicit product policy instead.
- `bingbot/2.0` and `MicrosoftPreview/2.0` are documented Bing crawlers/page-preview clients. Bing describes Bingbot as its standard crawler and MicrosoftPreview as generating snapshots for Microsoft products: [Bing crawler overview](https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0). Keep them out of conservative blocking/detection defaults.
- `Slackbot-LinkExpanding`, `Slack-ImgProxy`, and `Slackbot` are first-party Slack robots. Slack says the first fetches metadata for links users post, the second caches images, and the third supports product integrations: [Slack Robots](https://api.slack.com/robots). These are legitimate user-triggered fetches, not form bots.
- `Discordbot` is a legitimate preview fetcher. Discord documents `Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)`, says it visits links only when shared, and recommends IP verification because User-Agent values are spoofable: [Discord link previews](https://support.discord.com/hc/en-us/articles/42500550752919-About-Discord-Link-Previews-and-the-Discordbot). Exclude `Discordbot` from conservative defaults.

## Risks

User-Agent alone is advisory: all of these strings can be forged, and legitimate applications may use them. Google, Bing, and Discord explicitly warn about spoofing. Conversely, browser automation can use a normal browser UA, so this detector will miss it. A default block could reject integrations, CLI tooling, accessibility/testing traffic, or a user’s link preview. Apply these signatures only to the issue’s intended form path and combine with method, rate, session/CSRF state, IP/reputation, and request behavior; never use the UA match as authentication.

## Next action

Add the nine high-signal non-browser fragments as conservative candidates, keep crawler/preview signatures in an explicit allowlist or telemetry-only set, and add regression cases for versioned and decorated UAs. Before enabling enforcement, compare matches against production logs and document an override mechanism.
