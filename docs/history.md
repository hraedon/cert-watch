# Project history

cert-watch was built in the open between May and September 2026, mostly by
coding agents working under a human maintainer. That left a paper trail:

- about sixty numbered plans (`plans/`);
- a hundred and twenty session reflections (`reflections/`);
- the original work-item specifications (`docs/spec/`);
- a set of dated review reports (`docs/reviews/`).

They helped while decisions were being made. They don't describe the software
as it is, and a reader looking for that was more likely to be misled than
helped. So at 1.0 they left the tree. Nothing was lost:

- The git tag **`archive/pre-1.0-history`** points at the last commit that
  contains all of them. `git checkout archive/pre-1.0-history -- plans` brings
  a directory back, and GitHub's tree view at that tag browses them.
- `git log --follow <path>` from that tag still shows who wrote what, and why.

What replaced them:

- Current behaviour: [docs/](.) and the [README](../README.md).
- How the code is organised, and the invariants that hold it together:
  [architecture.md](architecture.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).
- What changed and when: the [changelog](../CHANGELOG.md).
- Why the product is shaped this way, including what it deliberately doesn't
  do: [positioning.md](positioning.md).

Two archived plans are worth reading for the reasoning behind 1.0. Plan 057,
*The road to 1.0*, reordered the maintenance work to fix the core before the
presentation layer. Plan 058, *Alerting is a package with one persisted
lifecycle*, designed the alert state machine described in
[alerting.md](alerting.md).
