# Scorer generation for run 20260827T000818Z-8e249763 (#2406)

This directory's `run.json` / `transcripts.jsonl` are stored records and are
never edited (see the repo-level README), so their scorer generation is
documented here instead.

The run was recorded **before** #2393 merged (#2402, 2026-08-27T01:11Z): it
uses the corpus scorer of tree `8e249763`, whose polarity matcher still lacked
the gerund/past prevention cues ("preventing", "prevented", "avoided",
"protecting against", "protected against") that #2402 added to
`polarity.py`.

That widening moves exactly one scored leg in this run: `safe_strcpy`'s
answer contains "...thus preventing buffer overflow", which the pre-widening
cue list penalized. Rescoring the stored answers with the current matcher
flips that leg -- `false_positive_ok: false -> true`, safe_strcpy 3/5 -> 4/5,
group hits unchanged, so a full recompute would read **54/69 instead of
53/69**. The measured text itself is untouched; only matcher semantics
differ, which is why the raw transcripts stay pinned by
`transcripts_sha256` rather than regenerated.

Any comparison between this run and a post-#2402 run must account for that
one-leg shift before reading a delta as model movement.
