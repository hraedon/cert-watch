# Project history

cert-watch was built between May and September 2026 in the open, mostly by
coding agents working under a human maintainer. That process left a paper
trail:

- about sixty numbered plans (`plans/`);
- a hundred and twenty session reflections (`reflections/`);
- the original work-item specifications (`docs/spec/`);
- a set of dated review reports (`docs/reviews/`).

They were useful while the decisions were being made. They aren't
documentation of the software as it is, and a reader looking for that was
more likely to be misled by them than helped. So at 1.0 they left the tree.
Nothing was lost:

- The git tag **`archive/pre-1.0-history`** points at the last commit that
  contains all of them. `git checkout archive/pre-1.0-history -- plans` brings
  a directory back, and GitHub's tree view at that tag browses them.
- `git log --follow <path>` from that tag still shows who wrote what, and why.

What replaced them:

- The current behaviour is described in [docs/](.) and the
  [README](../README.md).
- How the code is organised, and the invariants that hold it together, are in
  [architecture.md](architecture.md) and
  [CONTRIBUTING.md](../CONTRIBUTING.md).
- What changed and when is in the [changelog](../CHANGELOG.md).
- Why the product is shaped the way it is, including what it deliberately
  doesn't do, is in [positioning.md](positioning.md).

Two of the archived plans are worth knowing about if you want the reasoning
behind 1.0. Plan 057, *The road to 1.0*, reordered the maintenance work to fix
the core before the presentation layer. Plan 058, *Alerting is a package with
one persisted lifecycle*, designed the alert state machine described in
[alerting.md](alerting.md).
