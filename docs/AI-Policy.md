# AI-Assisted Contributions Policy

OhMyKeymint permits responsible use of AI coding assistants, but the project
evaluates the human contributor, not the tool. Trust depends on a real person
in the author and `Signed-off-by` chain who understands, can defend, and accepts
full responsibility for every submitted change. AI-generated content must meet
the same correctness, provenance, licensing, validation, and review standards
as human-written work.

## Disclosure is mandatory

Every pull request must state either that no AI was used or disclose every AI
tool and model used. For each disclosed tool, briefly describe what it did,
which parts of the contribution it affected, and how those parts were checked.
This includes using AI to find a problem, research, generate or modify code,
debug, review, test, write documentation, or draft commit and pull request
text. If the exact model or version is not available, say so rather than
omitting the tool. When in doubt, disclose.

For material AI assistance, also add the following trailer to the relevant
commit message:

```text
Assisted-by: LLM <tool and model>
```

Do not list an AI as an author, co-author, or `Signed-off-by` party. Only the
human contributor may certify that they understand the contribution, have the
right to submit it, and accept responsibility for it. AI output does not relax
the copyright, licensing, or authorization requirements in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Basic coding ability is required

AI assistance is not a substitute for basic coding ability. A contributor must
have enough proficiency in the affected language and subsystem to:

- understand every submitted change and its control, data, and error paths;
- explain why the change is correct and how it preserves required behavior;
- identify relevant edge cases, security concerns, and compatibility risks;
- run and interpret the required validation; and
- answer review questions and correct defects without blindly relaying AI
  output.

If you cannot understand and defend the entire contribution, do not submit it.

## Personal review and validation are required

The human contributor must personally and carefully review the complete final
diff, including every AI-generated or AI-modified line, before committing,
pushing, or opening a pull request. Reproduce the reported problem where
applicable, verify the proposed solution, and confirm correctness, security,
licensing and provenance, platform compatibility, project invariants, and the
absence of fabricated APIs, results, or evidence.

Run the validation required by [CONTRIBUTING.md](CONTRIBUTING.md) and report the
actual results. AI-generated code, explanations, reviews, and validation claims
are material to inspect, not authority to trust. They do not replace the
contributor's own review or real command output.

## Do not delegate the contribution to AI

Do not delegate the contribution workflow end to end to an AI. 

**An AI must not independently commit, push, open or update a pull request, 
send review replies, or merge a change.**

The human contributor must control these actions, inspect
the final staged or pushed diff and pull request text, and take full
responsibility for everything submitted under their identity.

Maintainers may ask a contributor to explain any part of a submission. A
contribution may receive additional review or validation requirements, be
deprioritized, ignored, or rejected when AI use is not disclosed, the
contributor cannot demonstrate understanding, the final change was not fully
reviewed, or the submission was autonomously delegated to AI. A polished
generated patch does not create an obligation for maintainers to investigate
claims that its human submitter has not verified.
