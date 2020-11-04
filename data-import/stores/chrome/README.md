# Chrome

Information on the special handling of certificates in chrome including certificates, blacklists, etc. can be found in their [repo](https://chromium.googlesource.com/chromium/src.git/+/refs/heads/master/net/data/ssl/)

Directory structure (Browse to the directory and read the README!):

* [`blocklist`](https://chromium.googlesource.com/chromium/src.git/+/refs/heads/master/net/data/ssl/blocklist/) (named `blacklist` in previous versions, c.f., [example](https://chromium.googlesource.com/chromium/src.git/+/72.0.3626.80/net/data/ssl/blacklist))
* `certificates`
* `ev_roots`
* `name_constrained`
* `root_stores`
* `scripts`
* `symantec`

## Blocklist

The blocklist directory lists certificates, however, the [`cert_verify_proc_blocklist.inc`](https://chromium.googlesource.com/chromium/src/+/master/net/cert/cert_verify_proc_blocklist.inc) lists SPKIs. Thus, the blocklist in fact blocks **full SPKIs**, not only the listed certificates. This was confirmed by Rob Stradling (email 2020-04-28) and is visible in the [README](https://chromium.googlesource.com/chromium/src/+/master/net/data/ssl/blocklist/README.md) which shows how the entries of `cert_verify_proc_blocklist.inc` are generated when adding a certificate to the blocklist.
