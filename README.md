# The World in One Day — Sunday 22 November 2026

A one-page digest of the day's world news, drawn as a single 1024×1024 PNG.

- Masthead naming Sunday 22 November 2026
- Lead: Iran strikes a US base in Kuwait as Gulf attacks widen
- 12 illustrated story cards, from Gulf tanker strikes to the ATP Finals
- A dotted world map with numbered pins matching the cards
- Region and field tallies counted from the same 41 stories
- A six-number day-in-numbers strip and 28 numbered briefs

## Run

```sh
node main.ts
```

The program writes `entry.png` to `/output` (or `$MAKEFUN_OUTPUT_DIR`).
It never draws or edits the picture: it audits the stored `entry.png`
(signature, chunk CRCs, header, pinned sha256, one full inflation) and
stages the exact bytes. Two runs produce byte-identical output.
