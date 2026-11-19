# CyberOK Defense Tools — ruby2shell

Network detection for **CVE-2026-132825**
([GHSA-34m4-m9fh-gqp5](https://github.com/ruby/ruby/security/advisories/GHSA-34m4-m9fh-gqp5)),
a one-byte heap buffer overflow in Ruby's string case conversion.

- **Fixed in:** Ruby **3.3.14 / 3.4.13 / 4.0.10** (released 2026-11-18).
- **Affected:** 3.3 ≤ 3.3.13, 3.4 ≤ 3.4.12, 4.0 ≤ 4.0.9. Older branches are end-of-life and get no fix.
- **Reported by:** Stephan Lipp (Ada Logics) and Anthropic.
- **Ruby advisory:** the team is "aware of PoCs that prove this flaw can be used to trigger RCE in some scenarios".

Updating Ruby is the fix. These rules help you see attempts.

| Component | File | Contents |
|---|---|---|
| **Suricata** | `suricata/ruby2shell.rules` | 3 signatures (SID 2202611001–2202611003) for Suricata 7 |
| **ModSecurity** | `modsecurity/ruby2shell.conf` | 2 chained rules (2202611010, 2202611020) for ModSecurity v3 (libmodsecurity) |

## The bug

Case conversion in Ruby's single-byte encodings can write one byte past its
output buffer when a string contains enough sharp-s characters (`ß`, 0xDF in
these encodings).

- **Encodings:** ISO-8859-1/2/3/4/9/10/13/14/15/16 and Windows-1250/1252/1254/1257.
- **Methods:** `upcase`, `upcase!`, `swapcase`, `swapcase!`, `downcase(:fold)` and `casecmp?`.
- **Fix:** [`d582f8f1`](https://github.com/ruby/ruby/commit/d582f8f13d700d8e39714d3a8f11eb4bd2bc69f0)
  on master; [`b841d6f4f1`](https://github.com/ruby/ruby/commit/b841d6f4f1b442ac9cc8de590b43f9e4ba6d3603)
  is the 3.4 backport.

Web applications are exposed when user input reaches these methods in an
affected encoding. Multipart form fields can declare such an encoding through
their `charset` parameter. The rules watch for that.

There is no remote version check here. On release builds the bug left no
visible effect in our tests, so a probe could not tell vulnerable from fixed
hosts. Check the Ruby version you run (`ruby -v`, the lockfile, the base image).

## Suricata

| SID | Fires on | Use |
|---|---|---|
| 2202611001 | the method-override form field (`_method`) declaring an affected charset, with an overflow-length run of 0xDF | primary |
| 2202611002 | any multipart field declaring an affected charset, with an overflow-length run of 0xDF | generic: application-level case conversion |
| 2202611003 | any `text/plain` part declaring an affected single-byte charset | low confidence: context and hunting |

The rules have no action other than `alert`. They match traffic from
`$EXTERNAL_NET` to `$HOME_NET` and read `http.request_body`, so Suricata must
see the body in cleartext. Deploy it behind TLS termination or feed it
decrypted traffic.

Suricata inspects only the first `request-body-limit` bytes of a request body
(100 KB in the default `libhtp` config). A field placed after a larger upload
falls outside that window. On sensors in front of Ruby apps, raise the limit:

```yaml
app-layer:
  protocols:
    http:
      libhtp:
        default-config:
          request-body-limit: 1mb
```

## ModSecurity

| ID | Fires on | Action |
|---|---|---|
| 2202611020 | `MULTIPART_PART_HEADERS:_method` declares an affected charset **and** `ARGS:_method` has an overflow-length run of 0xDF | `deny,status:403`, phase 2 |
| 2202611010 | any part declares an affected charset **and** any `ARGS` value has an overflow-length run of 0xDF | `deny,status:403`, phase 2 |

Requirements:

- `SecRequestBodyAccess On`, with multipart parsing enabled (the default).
- Load the file in phase 2, before any rule that would let the request through.
  With OWASP CRS, put it in `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`.
- Validated with CRS 4.30.0 on libmodsecurity 3.0.17.

ModSecurity parses the whole body up to `SecRequestBodyLimit`, so the
Suricata body window does not apply here.

## Validation and noise

Both rule sets were validated in our lab:

- **Positive traffic:** requests confirmed to trigger the overflow on ASan
  builds of Ruby 3.4.12.
- **Negative traffic:** benign multipart and URL-encoded forms.

Known noise:

- **2202611003** fires on any legitimate Windows-1252 or ISO-8859 form field.
  Use it for context, not blocking.
- **2202611002** can fire on uploaded text files (`filename=`) in an affected
  charset that contain many `ß`, such as German documents. The ModSecurity
  rules do not, because `ARGS` excludes file parts.

The rules match the multipart charset path only. Code that switches input
into an affected encoding by other means (for example `force_encoding`) and
then changes its case needs a code-level check.

## References

- Ruby advisory, 2026-11-18: <https://www.ruby-lang.org/en/news/2026/11/18/multiple-vulnerabilities-in-regexp-and-string/>
- GHSA-34m4-m9fh-gqp5: <https://github.com/ruby/ruby/security/advisories/GHSA-34m4-m9fh-gqp5>
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-132825>

Detection logic: CyberOK. See [LICENSE](LICENSE).
