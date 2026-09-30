# Threat Model Demo Part 3 - Asking Better Questions and Modeling Abuse Cases

In the first two parts of this demo, we:

* built a basic threat model for a public Hello World API
* generated a report and reviewed the risks it identified
* accepted or mitigated risks using the `risk_tracking:` block

At this point, the model contains more than enough information to start a useful conversations. In a real threat modeling exercise, the team or engineer creating the threat model should already thinking about, and including, these questions in the first or second iteration of the threat model.

Why? Because threat modeling is not only about generating a list of findings. It is also a structured way to identify assumptions, document unanswered questions, and ask how a feature could be deliberately misused.

This lesson introduces two optional Threagile fields:

* `questions:`
* `abuse_cases:`

Neither field automatically fixes a risk or changes a risk score. Their value is in making uncertainty, business intent, attacker behavior, and ownership visible while the design is still easy to change.

## The API We Are Modeling

Our application is still intentionally simple:

* A public client sends a JSON request to `/helloWorld`.
* The request contains a `name`.
* The Python HTTP service returns a greeting response.
* The endpoint is available over HTTP.
* The endpoint has no authentication or authorization.
* The endpoint processes input received from anonymous public clients.

The simple design is useful because it makes assumptions easy to spot. “Hello World” is often treated as harmless, but an internet-facing endpoint is still an exposed service with code, infrastructure, operational cost, and an attack surface.

The business may genuinely want anonymous access. That is a valid design decision. The question is whether the team understands what anonymous access permits, what it costs to operate, and what controls are appropriate for the intended use.

## Optional Fields Are Conversation Starters

A generated risk typically describes a known security condition. For example, Threagile can identify missing authentication because the communication link explicitly has `authentication: none`.

Questions and abuse cases solve a different problem:

* A **question** captures an important unknown that must be answered by a person or team.
* An **abuse case** describes an attacker or malicious user’s goal, method, and likely outcome.

These fields help prevent the model from looking more certain than the team actually is. If the model says the API handles only public data, but nobody has confirmed logging behavior, error handling, deployment details, or expected traffic volume, those are assumptions worth recording.

## Questions: Make Unknowns Visible

Questions should be specific enough that someone can answer them and should identify who is expected to provide that answer.

A poor question is:

```yaml
questions:
  Is the API secure?: ""
```

This is too broad to answer and does not produce an actionable decision.

A more useful question isolates a design decision:

```yaml
questions:
  What business capability requires this endpoint to be anonymously accessible from the public internet?: ""
```

This question does not assume authentication is required. Instead, it asks the business to verify why anonymous access is necessary.

Add questions to `sample-model.yaml` after the `risk_tracking:` block:

```yaml
questions: # simply use "" as answer to signal "unanswered"
  What business capability requires this endpoint to be anonymously accessible from the public internet?:  "The business has stated that this is just a demo API for training, see ticket INC000123"
  What normal and peak request volume should the API support, and what behavior is expected when that limit is exceeded?: ""
  What characters, length, encoding, and schema are allowed for the name value in the JSON request?: ""
  Are request bodies, client IP addresses, headers, errors, or response data written to logs, and how long are those logs retained?: ""
```

The important part is not the exact wording. The important part is that each question should be assigned, answered, and eventually reflected back into the threat model.

For example, if the business answers that the endpoint is only intended for an internal developer portal, then the model should change. The service may no longer belong on the public internet, and anonymous access may no longer be an acceptable risk.

## Questions by Stakeholder

Different people have different information. Threat modeling works best when questions go to the people who can actually answer them. 

| Stakeholder | Questions they should answer |
|---|---|
| Business or Product Owner | Who is the intended consumer? Is public anonymous access a requirement? What happens if the service is unavailable or abused? |
| Development Team | What input is allowed? How is JSON parsed? Are errors safely handled? Can response data reflect attacker-controlled input? |
| Operations or Platform Team | Where is the API hosted? Is TLS terminated upstream? Are logs collected? What rate limiting, WAF, DDoS, and monitoring controls exist? |
| Security Team | What public exposure is acceptable? What evidence is required to accept residual risk? What controls are mandatory for internet-facing APIs? |
| Legal, Privacy, or Compliance | Could users submit personal data despite the stated policy? Are IP addresses or request logs subject to retention or privacy requirements? |

A useful exercise is to choose one question and decide what model field should change after the team answers it. A threat model should evolve because an answer represents new information, not because the team wants the report to look better. 

## Abuse Cases: Think Like an attacker

An abuse case is not simply a vulnerability description. It starts with what an attacker, scraper, abusive customer, competitor, or curious researcher wants to accomplish.

For this API, an attacker may not care about receiving a greeting. They may want to:

* consume infrastructure resources
* test whether the endpoint can be used as a reflection mechanism
* submit payloads that appear in logs, dashboards, or downstream systems
* discover behavior differences through error messages
* use the endpoint as an early target while searching for other services on the same host or network
* create operational noise that hides a more serious event

The following abuse cases are appropriate for the hypothetical public greeting API:

```yaml
abuse_cases:

  Anonymous API Resource Exhaustion: >
    An attacker sends a high volume of requests, oversized JSON bodies, or
    intentionally slow requests to the public /helloWorld endpoint. Their goal
    is to consume CPU, memory, network capacity, log storage, or other shared
    infrastructure resources. The business impact is degraded availability,
    increased operating cost, and possible disruption of other workloads
    running on the same infrastructure.

  Hostile Input Through the Name Field: >
    An attacker submits unusually long values, control characters, markup,
    escape sequences, misleading log-like values, or sensitive data in the
    name value. Their goal is to cause unsafe behavior in request handling,
    reflected output, log viewers, dashboards, or downstream systems. The
    business impact could include misleading operational records, accidental
    sensitive-data retention, or an injection path if another consumer renders
    the returned greeting unsafely.

  Public Endpoint Reconnaissance: >
    An attacker submits malformed JSON, unexpected HTTP methods, unsupported
    content types, unusual encodings, and invalid headers to learn how the
    Python HTTP service behaves. Their goal is to identify implementation
    details, error-handling differences, stack traces, supported capabilities,
    or adjacent exposed services. This information can reduce the effort needed
    to find and exploit a separate weakness.

  Reflected Content Abuse: >
    An attacker supplies crafted input to the name field and distributes the
    resulting response to another user or system. Their goal is to turn the
    greeting response into a delivery mechanism when a browser, terminal,
    dashboard, log viewer, or another client renders the attacker-controlled
    content without appropriate output encoding.

  Unexpected Sensitive-Data Submission: >
    A user submits personal, confidential, credential, or other sensitive data
    in the name field despite the application requirement that PHI and PII are
    not allowed. The risk is not that the API is designed to process sensitive
    data, but that untrusted users can ignore intended use and cause sensitive
    content to appear in logs, error records, monitoring systems, or support
    workflows.

  Abuse of an Accepted Anonymous-Access Decision: >
    An attacker takes advantage of the accepted decision that the endpoint has
    no authentication. Their goal is not necessarily to access protected data,
    but to use unrestricted access for automated probing, resource consumption,
    behavior discovery, or as a stable public service in a broader attack
    workflow. The team should periodically confirm that the public,
    unauthenticated design remains a valid business requirement.
```

## Turning an Abuse Case Into a Test

An abuse case should influence engineering work. It is not complete just because it appears in YAML.

Take the `Anonymous API Resource Exhaustion` abuse case. A practical team response might be:

1. Define a maximum accepted request-body size.
2. Define a maximum length for `name`.
3. Reject invalid JSON and unsupported content types.
4. Add a rate limit at the edge or reverse proxy.
5. Add automated tests for oversized and malformed requests.
6. Add monitoring for abnormal request volume and high error rates.
7. Re-run the threat model after the architecture or controls change.

This is the connection between threat modeling and DevSecOps: an abuse case becomes a security requirement, then a backlog item, then an implementation and test, then evidence for a mitigation decision.

## Do Not Confuse a Question With a Mitigation

Adding a question does not reduce risk.

Adding an abuse case does not reduce risk.

Adding a control that is not implemented does not reduce risk.

A risk should only be marked as mitigated when the team can explain what control exists, where it is enforced, how it is tested, who owns it, and how it will remain effective as the application changes.

For example, saying “the API will be rate limited” is an intention. A stronger mitigation statement identifies the enforcement point and evidence:

```yaml
description: >
  Anonymous public clients could exhaust API resources through high request
  volume or oversized requests.
status: mitigated
justification: >
  The edge proxy enforces a 100 requests-per-minute limit per source address,
  rejects request bodies larger than 4 KB, and exports rate-limit events to
  centralized monitoring. Automated integration tests verify both controls.
ticket: API-123
date: 2026-01-03
checked_by: Alice
```

The mitigation becomes more credible because it is specific, testable, and owned.

## Suggested Exercise

Before continuing, review the model as if the greeting API will be deployed next week.

Choose one of the questions above and write an answer from the perspective of the stakeholder who owns it. Then identify one field in `sample-model.yaml` that should change because of that answer.

For example:

* If the endpoint must be public, what evidence supports accepting anonymous access?
* If the endpoint is only for internal developers, what trust boundary and communication-link changes are necessary?
* If the API logs request values, what data classification and retention changes are necessary?
* If the API must tolerate high public traffic, where should rate limiting be enforced?

In the next part, we can use these answers and abuse cases to define security requirements, add technical controls, and show how model changes affect the generated report.

[Moving to Continuous Threat Modeling](link_to_next_branch)