# CSS rules needed in tokens.css (requested by Activity conversion)

## Filterbar select sizing

```css
.cw-filterbar .cw-select { width: auto; }
```

**Why:** `.cw-select` is `width: 100%`, which is right for its home inside
`.cw-field` column layouts, but inside the flex `.cw-filterbar` row it makes a
bare select claim the entire row and wrap the remaining controls (visible on
/audit's target-type filter). The filterbar is documented as "search +
segments + spacer + secondary controls", so selects placed in it should size
to their content like the other controls do. Scoping by context (`.cw-filterbar
.cw-select`) needs no new class and keeps the one-filter-bar paradigm intact.

## Print: hide breadcrumbs

```css
@media print {
  .cw-crumbs { display: none !important; }
}
```

**Why:** The report pages (/reports/compliance, /readiness) now open with a
`.cw-crumbs` breadcrumb back to /posture. The `@media print` block in
tokens.css hides the topbar, page actions, filter bars, etc., but not
`.cw-crumbs`, so a printed report leads with "Posture › Compliance report"
navigation chrome. Add `.cw-crumbs` to the print hide list (requested by the
compliance/readiness conversion; per-template `<style>` blocks are banned so
it can't be patched locally).
