# Contributing to Latch

Thank you for helping with Latch.

## Build and test

Run these commands from the repository root:

```
rebar3 compile
rebar3 eunit
rebar3 dialyzer
rebar3 escriptize
```

The EUnit suite must pass. Dialyzer must report no warnings.

## Code style

Match the style of the surrounding code. Keep functions small. Write a short
module comment and a spec for each public function. Use only the standard
library and OTP.

## Tests

Add a test for every new behaviour. Add negative tests for failure cases.
Keep tests deterministic. Do not depend on network access or timing.

## Commits

Write a clear commit message. Explain what changes and why. Keep each commit
focused on one change.

## Reporting bugs

Open an issue. Describe the expected result and the actual result. Include
the Erlang version and the steps to reproduce.

## Security issues

Read `SECURITY.md` first. Do not open a public issue for a security problem.
