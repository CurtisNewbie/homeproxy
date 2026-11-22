# 02: Docs and ADR state the new rule

**What to build:** Every place that documents how host-list entries match reads the new rule: a
`*.suffix` entry covers the suffix host and its subdomains, an exact entry covers that host alone.
`doc/config.md` is regenerated from the annotations, never hand-edited. An operator reading the
README, the samples or the glossary learns the rule and what it costs: nothing expresses
"subdomains only" any more.

**Blocked by:** 01 — `doc/config.md` is generated from the property annotations ticket 01 rewords.

**Status:** done

- [x] `doc/config.md` regenerated with `misoconfig -path doc/config.md` and matches the annotations
- [x] README's PAC section and its `homeproxy.bypass` paragraph state the wildcard-apex rule and that
      exact entries do not match subdomains
- [x] the glossary's host-list term carries the new meaning
- [x] the sample configs' comments describe the new meaning; their entries need no structural change
- [x] `docs/adr/0006-wildcard-covers-apex.md` records the rule, its trade and the alternatives
      rejected