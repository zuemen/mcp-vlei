# The measurement

Everything else in this repository is a solution. This directory is the problem it answers, made
executable — the experiment behind `docs/PROBLEM.md` §5 and the opening of the talk.

**Nothing here is run against any third party's service.** The server is `vendor_server.py`, in this
directory. The policy it applies is ours, written to be measured.

```bash
pip install -e packages/mcp-vlei
python examples/impersonation/spoof_client.py
python examples/impersonation/edge_test.py
```

## The server does what the specification says not to do

MCP states that `clientInfo` MUST NOT be used to change behaviour or make security decisions.
`vendor_server.py` uses it for exactly that: a caller whose self-reported name contains `claude`
gets a 100-hour partner allowance; everyone else gets one hour.

That this policy is unwise is not the finding. The specification already says so. The finding is
that **the protocol layer cannot tell the difference** — there is no verified statement to compare
`clientInfo` against, so a server that wants to make this distinction has nothing else to use, and
a server that refuses to make it has nothing to put in its place.

## One binary, three runs, one variable

`spoof_client.py` requests 50 GPU hours three times. The only thing that changes is `client_info`.

| Run | `clientInfo.name` as received | Tier | Approved |
|---|---|---|---|
| honest | `zuemen-script` | default | **1 hour** |
| impersonating | `Claude Desktop` | partner | **50 hours** |
| omitted | `mcp` | default | **1 hour** |

The impersonating run sends everything a well-known client would plausibly send — version,
description, `websiteUrl`. None of it is checked by anything.

The third row is the one people miss. Omitting `client_info` does not send nothing: the SDK
supplies its own default, so the server receives a name either way. **There is no way to decline to
identify yourself**, only a choice between claims.

## What the fields will accept

`edge_test.py` asks a narrower question: is anything about the claim checked?

| Case | Outcome |
|---|---|
| wrong type for `version` | rejected by validation |
| wrong type for `name` | rejected by validation |
| extra unknown field (`trustLevel: high`) | accepted |
| 4096-character name | accepted |
| `websiteUrl` that is not a URL | accepted |
| `websiteUrl: javascript:alert(1)` | accepted |
| icon `src` as a `data:text/html` URI | accepted |
| icon `src` as `file:///etc/passwd` | accepted |
| empty name | accepted |
| name claiming another vendor | accepted |

Nine of eleven reached the server unchanged. **Types are validated; semantics are not.**

Read this carefully, because it is easy to overstate and an expert will catch an overstatement.
A field being accepted is not a vulnerability: the specification says not to trust these fields, so
carrying them unchecked is consistent with what they are for. What the table shows is that nothing
downstream can distinguish a careful claim from a careless one — the same gap as the table above,
from a different angle.

The two validation rejections are worth noting in the other direction: the SDK does check what it
promises to check. This is not sloppiness. It is a field that was never meant to bear weight, being
asked to bear weight because nothing else is available.

## What this establishes, and what it does not

**Establishes.** A server making an authorization decision from `clientInfo` cannot be prevented
from doing so, cannot be detected doing so, and cannot distinguish an honest caller from one
claiming to be someone else.

**Does not establish.** That any real service does this. That MCP has a vulnerability. That the
SDK is careless. The specification's guidance is correct, and this is what its absence of an
alternative costs.

## The alternative, in the same terms

With `org.gleif.vlei/identity`, the same three runs produce a different table: two are refused at
`missing_credential`, and the third presents a credential chained to a root the server accepts,
carrying an LEI that a registrar issued and can withdraw.

That comparison is the first thirty seconds of the recording — scene 0 and scene 1 of
`examples/console/`, the same layout, the difference being whether the request carries four keys
and whether the right-hand column has anything to run.
