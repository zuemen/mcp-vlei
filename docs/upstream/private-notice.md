# Notice to GLEIF, alongside the public issue

**Status: draft, not sent.** Send it yourself; nothing in this repository sends anything.

## What was considered, and why the recommendation is "same day"

The defect in [`issue-final.md`](issue-final.md) lets an **unauthenticated** request take
`vlei-verifier` down when revocation checking is enabled: a presentation that fails verification
stores a state with no AID, and the revocation observer then uses `None` as a database key and
exits. Reproduced live on 1.0.0 and 0.1.5 on 2026-09-24 ([`README.md`](README.md)). The exposure is
limited — `revocationCheck` is off in the shipped configuration — but it is a denial of service
reachable without credentials.

A defect like that would normally go to the maintainers privately first. Two facts decide against
waiting here:

- **It is already public.** The first write-up, with its reproduction, has been in this public
  repository since 2026-09-23 (`docs/upstream/issue.md`), and `issue-final.md` since 2026-09-24.
  Holding the GitHub issue back would delay the maintainers learning of it, not anyone else.
- **GLEIF publishes no security contact.** There is no `SECURITY.md` in GLEIF-IT/vlei-verifier,
  private vulnerability reporting is not enabled on the repository, `gleif.org` has no
  `security.txt`, and the [contact page](https://www.gleif.org/en/contact/contact-information) lists
  only `info@gleif.org` for general enquiries.

So: file the issue, and on the same day send the note below, so a person at GLEIF hears of it
directly rather than from a notification.

## The note

**To:** info@gleif.org
**Subject:** vlei-verifier — denial of service in the revocation observer (GitHub issue filed)

> Hello,
>
> I have filed an issue on GLEIF-IT/vlei-verifier that I think the maintainers should see soon, and
> could not find a security contact for the project, so I am writing here as well. Could you
> forward this to whoever maintains vlei-verifier?
>
> In short: with revocation checking enabled, an unauthenticated request can cause the service to
> exit. A presentation that fails verification stores a credential state without an AID; the
> revocation observer later uses that missing AID as a database key, keripy raises a TypeError, the
> handler for that error repeats the same write, and the process ends. Because the service's
> databases are temporary, a restart also discards every earlier presentation. It reproduces on the
> 1.0.0 and 0.1.5 images. The shipped configuration has revocation checking off, which limits the
> exposure.
>
> The issue — with a minimal reproduction, the traceback from both tags and three suggested fixes —
> is at: <link to the issue>
>
> I found this while building an open-source MCP extension on the vLEI ecosystem
> (github.com/zuemen/mcp-vlei). If there is a better channel for reports like this, I would be glad
> to know it.
>
> Thank you,
> Ting-Yi Chu
