# Contributing

## Add a source
1. **Check the source first:** a public page or document from the vendor or project itself (not a reseller copy), robots.txt allows it, and it states support or longevity dates or a dated policy.
2. **Write one parser** in `supportdates/sources.py` that turns the page into `Record`s: component, line, date, kind (`official` = stated, `derived` = computed from a published policy, `notice`), source URL and a short evidence quote.
3. **Add a test** in `tests/` with a small, trimmed excerpt of the real page. Cover the layouts you have seen (merged cells, "TBD" rows, renamed items).
4. **Failure mode:** if the source can't be fetched or parsed, the collector carries its previous records forward. A parser must never produce false "removed" events.

## Report a wrong date
Open an issue with the record, the source URL and what the source says. Corrections show in the change log; nothing is rewritten silently.

## Rules
- Facts with sources only: no rankings, scores or judgements of vendors.
- Standard library only; `make test` must pass.
- AI-assisted changes are marked in the commit message (`Co-Authored-By:` line naming the model).
