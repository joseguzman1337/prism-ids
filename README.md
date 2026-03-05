<div align="center"><img alt="prism" src="./images/logo.svg"></div>

# An Optimizing Suricata-Rule Compiler

## Overview
PRISM is a suricata(tm) rule parser, analyser and compiler. It uses techniques
from compiler theory to open up sophisticated optimisations and new
applications of rulesets such as ETOpen(tm) as well additional static analysis
for helping rule-authors to quickly catch bugs in their rules.


## Usage
Run the following commands:

```bash
make -C output clean
python -m prism --refract /path/to/ruleset
python -m prism --translate prism.{tls,dns}.rules -o ./output
make -C output
```

This will create an executable called `output/bin/prism`

```bash
$ output/bin/prism --help

Prism test program

Usage:
  Test the rules:
    --hook=dns_request
    --hook=tls_client
    --hook=tls_server

  Buffers:
    --pkt-data=STRING
    --dcerpc-stub-data=STRING
    --dnp3-data=STRING
    --dns-query=STRING
    --file-magic=STRING
    --file-name=STRING
    --http-accept=STRING
    --http-accept-enc=STRING
    --http-accept-lang=STRING
    --http-connection=STRING
    --http-content-len=STRING
    --http-content-type=STRING
    --http-cookie=STRING
    --http-header=STRING
    --http-header-raw=STRING
    --http-header-names=STRING
    --http-host=STRING
    --http-host-raw=STRING
    --http-location=STRING
    --http-method=STRING
    --http-protocol=STRING
    --http-referer=STRING
    --http-request-body=STRING
    --http-request-line=STRING
    --http-response-body=STRING
    --http-response-line=STRING
    --http-server=STRING
    --http-start=STRING
    --http-stat-code=STRING
    --http-stat-msg=STRING
    --http-uri=STRING
    --http-uri-raw=STRING
    --http-user-agent=STRING
    --http2-header=STRING
    --http2-header-name=STRING
    --icmpv4-hdr=STRING
    --icmpv6-hdr=STRING
    --ipv4-hdr=STRING
    --ipv6-hdr=STRING
    --ja3-hash=STRING
    --ja3-string=STRING
    --ja3s-hash=STRING
    --ja3s-string=STRING
    --krb5-cname=STRING
    --krb5-sname=STRING
    --mqtt-subscribe-topic=STRING
    --mqtt-unsubscribe-topic=STRING
    --rfb-name=STRING
    --smb-named-pipe=STRING
    --smb-share=STRING
    --snmp-community=STRING
    --ssh-hassh=STRING
    --ssh-hassh-server=STRING
    --ssh-hassh-server-string=STRING
    --ssh-hassh-string=STRING
    --ssh-proto=STRING
    --ssh-software=STRING
    --tcp-hdr=STRING
    --tls-cert-fingerprint=STRING
    --tls-cert-issuer=STRING
    --tls-cert-serial=STRING
    --tls-cert-subject=STRING
    --tls-certs=STRING
    --tls-sni=STRING
    --udp-hdr=STRING
```


## Implemented Transforms
### Front-end (lexing and parsing)
 - Basic parsing of rule heads, and options
 - Folding of content modifiers in to content options
 - Rule thresholding extraction
 - sticky buffer allocation
 - parse and extract flowbits
 - parse and extract buffer transforms


### IR Transforms
- hook-determination: We figure out where a rule belongs based on it's protocol
  and what fields it is matching, eg. we can distinguish tls client from tls
  server matches.
- Startswith idiom detection:
  - `content:"abc"; depth:3;`
  - `content:"abc"; depth:3; offset:0;`
- Endswith idiom detection
  - `content:"abc"; isdataat:!1,relative`
- Exact matches: content/buffer-size idiom recognition, various formulations
  of this are supported:
  - `content:"abc"; depth:3; endswith;`
  - `content:"abc"; depth:3; startswith; endswith;`
  - `content:"abc"; bsize:3;`
  - `content:"abc"; depth:3; isdataat:!1,relative;`
- Hex untransforms: Some buffers like `tls.ja3` or `tls.cert_fingrprint` are
  hex-encoded by suricata. We can un-apply this hex-transform of the content so
  that we can match against the raw binary. If the data-size of the field is
  known (eg. `tls.ja3` is 16 bytes) then we can also convert matches in to
  exact matches.


### RTL Transforms / Optimizations
- Multi-pattern match prefilter (for every buffer used)
- Buffer-match ordering optimisation to minimize state required between
  buffer-matches


## Planned Optimizations and Features
### Shortcut Evaluations
For some rule-sets we may be able to structure the ordering of operations in
such a way as that if there are no matches for the earlier fields, then we can
short-cut progressing to the later fields. I'm not sure how much this would
actually add in practice. I think, depending on how this is implemented, it
would either never apply, or it would apply but sometimes require us to split
hyperscan databases. Another possibility would be to identify if there are some
hyperscan databases we can prefilter based on a previous matches bitset.

### Relative Content Matches
We should be able to implement these as a chain of operations, aka. "rule-tails"
from the `ryuk` compiler. Should be straightforward. One question is whether we
will use hyperscan for simple string matches, pre-computed BM tables ala
`ryuk`, or some generated-code which makes use of SSE4.2. Probably the latter
would be fastest. This feature will allow us to support packet-content rules
and, therefore, the vast majority of ET-open.
