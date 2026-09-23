# Activity surface brief

## Purpose

Activity provides evidence of what happened and when. Its alert, scan-history,
and audit tabs answer: what was detected or attempted, did delivery or scanning
succeed, and which actor changed which object?

## Structure

**Archetype:** Activity / log. Each tab is a dense, filterable,
reverse-chronological table with absolute timestamps, explicit state, and
object links. Tabs separate event kinds without changing the page grammar.

It must show alert lifecycle and delivery state, scan endpoint/result/error,
and audit timestamp/actor/action/target/detail. Empty results and delivery or
scan failures must remain explicit; pagination and filters must retain scope.

## Ownership and boundaries

Activity owns historical evidence and investigation. It does not own current
triage priority, certificate truth, retry policy, alert routing configuration,
or user administration. It must not become an avatar feed or use relative time
for audit evidence.
