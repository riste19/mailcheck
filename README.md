# Mailcheck

A free email verifier with no paid verification API, API key, package installation, or credits. Node.js 20+ is required for the local version.

## Start on Windows

Extract the entire downloaded ZIP, then double-click `Start-Mailcheck.cmd`. Open http://127.0.0.1:4317 and keep the terminal open. Alternatively run `npm start` from this folder. Stop with Ctrl+C. The server binds only to your computer's loopback interface.

## Using it

Paste email addresses, one per line, or import a CSV with an `email` or `email address` column. A `status`, `verification_status`, `email_status`, `hunter_status`, or `result` column is retained as imported evidence, never represented as a fresh check. Use batches of up to 5,000 rows or 5 MB. Add any bounced, opted-out, or previously contacted addresses to the suppression list before running checks. Matching is case-insensitive; it does not strip plus tags or Gmail dots. There is no Gmail connection or automatic suppression discovery.

The local app enables the **Mailbox + catch-all probes** option. Select it before clicking Verify. The hosted website runs syntax and DNS checks; it cannot open outbound SMTP connections. The local download contains the same interface plus the SMTP backend.

## Checks included

- Common ASCII email syntax, domain labels and address length. Quoted/international addresses need specialist verification and stay unsupported rather than being marked invalid.
- Live MX records, explicit null MX, nonexistent domains, and A/AAAA fallback if no MX record is advertised.
- A bundled community disposable-domain list, common provider typo suggestions, role addresses, and duplicate rows. Risk flags need review; a role address is not inherently invalid.
- Local SMTP greeting, recipient acceptance, and a random recipient test for catch-all behavior. No DATA command or email body is ever sent. There are at most two probes running at once, each bounded to 25 seconds.
- Suppression matching, result filtering, pagination and CSV export with evidence and check timestamps. CSV formula-like cells are escaped.

## Interpreting results

**Domain passed:** syntax and mail-routing checks passed; the inbox is not confirmed.

**SMTP accepted:** the server accepted the requested recipient and explicitly rejected a random recipient as nonexistent. This is evidence, not a delivery guarantee.

**Catch-all:** the server accepted both requested and random recipients. The specific inbox is still uncertain.

**Rejected:** a recipient-level response explicitly indicated a nonexistent mailbox. Generic 550 policy rejections, 4xx temporary errors, forwarding responses, timeouts, unavailable IPv4, stay unknown. Recipient acceptance with inconclusive catch-all evidence is reported separately as accepted-unconfirmed.

**Suppressed / duplicate / needs review:** examine the flags and evidence. Imported statuses are historical labels only. Results never authorize or send outreach.

## Network limitations

Many home networks, ISPs, and cloud providers block outbound TCP port 25. Many mail servers hide inbox existence or reject null senders. This release reports those cases as unknown. No software can force a remote server to reveal a mailbox. The SMTP backend uses IPv4 and upgrades to STARTTLS with certificate verification when advertised. Servers without STARTTLS receive plaintext SMTP commands; recipient addresses and your IP are visible to the receiving server. It deliberately does not attempt to bypass blocks, use proxies, or retry aggressively. Set `MAILCHECK_HELO` to your actual fully qualified sending hostname if you have one; otherwise it honestly identifies the local socket's IP literal.

No paid mailbox-verification provider, contact discovery database, reputation network, or historical delivery database is included. A network or server where SMTP is allowed can improve coverage, but no hosting purchase is required to run locally. If your ISP blocks port 25, DNS checks still work.

## Privacy and data

Lists and results are held in browser memory and clear on reload. Export results before closing. The local server does not persist or log recipient addresses. Domain names are queried through Cloudflare DNS over HTTPS with Google DNS fallback. Enabling SMTP probes shares recipient addresses with their destination mail servers without submitting a message. Font files load from Google Fonts. No account, email sending capability, or paid API key is needed.

The disposable-domain snapshot comes from https://github.com/disposable-email-domains/disposable-email-domains under its public-domain license, included in `dist/disposable-list-LICENSE.txt`. The list is not exhaustive or guaranteed current. Update with `node update-disposables.mjs` and restart/reload the app.

Technical references: https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/ and https://www.rfc-editor.org/rfc/rfc5321.html.

## Checks for developers

Run `npm test`. No dependencies are installed. `PORT` may override 4317, but use the printed 127.0.0.1 URL. Native DNS resolves the mail host to a pinned public IPv4 address; private and reserved ranges are rejected. The probe endpoint accepts only same-origin JSON POST requests.

## DNS reliability update

Both browser checks and local probes use HTTPS DNS with Cloudflare and Google fallback, rather than Node shared UDP DNS lookups. A failed DNS check is labelled Check failed and never treated as invalid. Export includes check_failed and dns_resolver. The Previous Hunter results input joins historical statuses by email, and the Previous result column keeps them separate from fresh Mailcheck evidence. Export/reimport preserves imported_status. Download and extract the latest local package to receive these changes.

## Evidence and retry update (rules 2026-11-03.3)

Recipient status and catch-all status are independent. `accepted` means the real recipient received 250 and the random recipient was explicitly rejected as nonexistent. `accepted-unconfirmed` means the real recipient received 250 but the catch-all test is inconclusive. Risk flags such as role addresses do not erase SMTP acceptance. Neither acceptance state guarantees delivery.

The Microsoft-specific rule applies only to a mail host under mail.protection.outlook.com, with the exact 550 5.4.1 recipient-address rejection signature and Microsoft's EXOSmtpErrors link, after the real recipient received 250. Other generic 550 replies are not promoted. Source: https://learn.microsoft.com/en-us/troubleshoot/exchange/email-delivery/ndr/fix-error-code-550-5-4-1 . Rules are versioned and the matching rule is exported.

A connection failure tries at most one additional advertised MX, ordered by priority. Policy rejections, certificate failures, and completed checks do not trigger alternate-host probing. An address can take up to 50 seconds including the backup server. Temporary failures can be retried manually after 15 minutes, up to three attempts per imported or active record. Keep the app open; no background automation runs. Successful rows are excluded from the retry queue. Stop cancels starting more rows; an in-flight local server connection remains bounded by its timeout.

Use Review a saved Mailcheck export to reinterpret saved responses without any network probes. The original checked_at is kept and reviewed_at and evidence_origin distinguish interpretation from a fresh check. Reloading clears the session; export your work. Retry eligibility and current attempts are exported for resuming.

Import observed outcomes with columns email,outcome,observed_at. Allowed outcomes: reply, delivered, hard_bounce, soft_bounce. Use an ISO timestamp including timezone, for example 2026-11-03T13:00:00Z. Only actual observed events belong here; absence of a bounce is not delivered evidence. There is no automatic Gmail access. Events before a prediction are excluded; conflicting hard-bounce and positive events stay conflicting. The observed hard-bounce fraction among SMTP-accepted addresses with usable outcomes is a selected-sample metric, not an overall accuracy claim. No message is sent by this feature.

## v4: provider rules and bulk diagnostics

Rules 2026-11-03.4 recognize the documented Microsoft consumer 550 5.5.0 mailbox lookup response on *.olc.protection.outlook.com only when the S2017062302 signature matches. Microsoft DBEB rejections of the real recipient are now reported as rejections, rather than policy unknowns. Google 550 5.2.1 DisabledUser replies on Google mail hosts are reported as inactive/disabled rejections. Generic 550 replies remain inconclusive. These are interpretations of server responses, never delivery guarantees.

Temporary sender-stage 4xx failures now remain eligible for cooldown retries. Diagnostics explain greeting rejection, policy blocks, certificate issues, and temporary failures. MAILCHECK_HELO can identify your own legitimate fully qualified mail hostname; the app does not invent a sending identity or bypass server blocks. TLS certificate checks remain enabled.

Backend MX and IPv4 records are cached only for their TTL, up to five minutes, in a bounded 256-entry cache. Failed queries are not cached. This reduces repeated DNS work on large lists without storing recipient addresses.

Use node review-export.mjs input.csv new-output.csv to review saved exports offline. Input is never overwritten; output includes original_result, original_mailbox_status, checked_at, reviewed_at and evidence_origin. It sends no probes. References: https://learn.microsoft.com/en-us/troubleshoot/exchange/email-delivery/ndr/non-delivery-reports-in-exchange-online and https://support.google.com/mail/answer/3726730?hl=en .
