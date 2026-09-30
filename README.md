# Threat Model Demo Part 2 - Checking and Mitigating Risks

Now that we've created a threat model and generated a report we'll want to
* review the risks
* update the model
* regenerate the report with each update to reflect updates

## Reviewing Risks
There are a number of ways to review your risk outputs, but the most programmatically oriented way may be to review the [JSON Risk Regstry](./report/risks.json).  For a more visual friendly format, there is also an [Excel Spreadsheet](./report/risks.xlsx).

Let's examine one of the easiest risks to mitigate for this threat model - Missing Authentication

``` jq '.[] | select(.category == "missing-authentication")' risks.json```

```json
    {
        "category": "missing-authentication",
        "severity": "elevated",
        "exploitation_likelihood": "likely",
        "exploitation_impact": "medium",
        "title": "<b>Missing Authentication</b> covering communication link <b>Public Greeting API Request</b> from <b>Public Clients</b> to <b>Python HTTP Service</b>",
        "synthetic_id": "missing-authentication@public-clients>public-greeting-api-request@public-clients@python-http-service",
        "most_relevant_technical_asset": "python-http-service",
        "most_relevant_communication_link": "public-clients>public-greeting-api-request",
        "data_breach_probability": "possible",
        "data_breach_technical_assets": [
        "python-http-service"
        ]
    }
```

You'll want to take note of the ```synthetic_id``` for this risk.  This is a unique id generated for each risk and should be specific to each asset.   You wouldn't want a blanket "Missing Authentication" risk because your endpoints could be a mix of those to should and shouldn't use authentication.  There is a way to wildcard a mitigation to several risks at once, but I wouldn't recommend it.

## Risk Acceptance and Mitigation

If you recall the requirements you'll remember that authentication wasn't listed.  The business intent was to simply have a Hello World type API.  To update our threat model we're going to open our model and add a new section.

All of our updates will go into the ```risk_tracking:``` block of the yaml.  Because it was an optional element, and because we need the unique ```synthetic_id``` of the risk to even action those items, we couldn't have even included this in the initial model.

We'll title each element by it's synthetic id. 

```yaml
    risk_tracking:
        missing-authentication@public-clients>public-greeting-api-request@public-clients@python-http-service:
            description: The public clients can access the API without any authentication, which is a risk.
            status: accepted
            justification: >
            This is a public API that is meant to be accessed by anyone, so we accept the risk of missing authentication.
            ticket: N/A
            date: 2026-01-02
            checked_by: Alice
```

If we now regenerate our [report](./report/02-accpeted_risk_report.pdf), we'll notice a number of changes.

First you'll notice the summary which now shows one risk has been accepted.

![Management Summary Pie Chart](./images/01-AcceptedPieChart.png)

The next update is to the Risk Mitigation details which, honestly, just presents the risks with a couple of more specific charts and graphs.

![Risk Mitigation charts](./images/01-TrackingStatus.png)

Rather than nitpick every single change in the report for this change, let's look at the most signficant changes.  Under the Risk Findings for Missing Authentication, and under the Python HTTP Service, we will now have these updated findings.

First, within the defined risk, is the updated finding

![Risk Finding Updated Description](./images/01-MissingAuth-Finding.png)

Next, we'll see a similar update in the Python HTTP Service

![Accepted Risk for Python HTTP Service](./images/01-AcceptedHTTPServiceAuth.png)

**NOTE:**  While this covers what you would expect to see, there is one detail you might be wondering about.

In the Risk Mitigation section early in the report, it details the status of the risks and that we've accept 1 of these risks.   However, in the following section for Impact Analysis, 10 of 10 risks are still listed as remaining.

![Impact Analysis with 10 risks](./images/01-ImpactAnalysis.png)

Why?  This is because we've accepted the risk instead of mitigating the risk or otherwise negating it in some other way.  Should we make a change to this endpoint and the business intent is that authentication is required, we have no mitigation and the risk still remains.  To prove that with a different risk, lets actually mitigate the Second Factor Authentication risk.  If authentication isn't required, or even possible in this case, then this risk is mitigated.

```yaml
    missing-authentication-second-factor@public-clients>public-greeting-api-request@public-clients@python-http-service:
        description: All methods of authentication should require MFA
        status: mitigated
        justification: >
        We don't allow authentication at all, so MFA is pointless.
        ticket: N/A
        date: 2026-01-02
        checked_by: Alice
```

With the new mitigation added to the model we can re-run the [report](./report/03-mitigated_risk_report.pdf) and confirm that, instead of 10 remaining risks, we now only have 9.

![Impact Ananlysis with 9 risks](./images/02-RiskMitigatedProven.png)

Lastly, lets mitigate a risk that should have a significant impact within the report.   One of the highest rated risks is listed as Untrusted Deserialization.  Within the Python HTTP Service we define the following

```yaml
    data_formats_accepted: # sequence of formats like: json, xml, serialization, file, csv
      - json
      - serialization
```

I wanted to show the risks of untrusted input in the initial threat model and have a way to show how it impacts a report.  So, I put serialization as an accepted format.  This is because, at least with Python, there are several ways to consume this API request.

The safer way would be with ```import json``` with ```json.loads``` to read the request.  However, there is a very unsafe way with ```jsonpickle``` and ```jsonpickle.decode``` which will deserialize a json object and potentially allow remote code execution.

The more obvious way to fix this risk is to use the safer method and remove serialization as an accepted format. However, to show how mitigating this affects the report, lets deal with the latent risk instead.

```yaml
    untrusted-deserialization@python-http-service:
        description: The API endpoint could deserialize the JSON payload sent by the public clients, which is untrusted input.
        status: mitigated
        justification: >
        The API endpoint will use a safe deserialization library that prevents code execution and other attacks.
        ticket: N/A
        date: 2026-01-02
        checked_by: Alice
```

Now if we run our [report](./report/04-significant_risk_mitigated_report.pdf) again and look at the Data Mapping Chart we'll see that our report has changed in a positive way.

![Data Mapping Risk decreased](./images/DataMappingMitigated.png)

Previously, the objects were red, indicating more risk.

![Data Mapping Risk unmitigated](./images/DataMapping.png)

## Undefined Risks

What If Threagile Does Not Identify a Risk? The generated report is based on the rules Threagile knows about and the details captured in the model. That does not mean a risk is not real just because it is missing from the report.

A team might identify a risk during architecture review, testing, an incident, vulnerability research, or because of a new CVE/CWE pattern. For example, a new zero-day affecting a dependency or a business-logic weakness might not have a built-in rule yet. In that case, we can add the finding directly to the model with individual_risk_categories.

This creates a risk finding that appears in the report and can be managed through the normal risk_tracking workflow. It is not automatic detection. The team is documenting a known risk until it is mitigated, accepted, determined to be a false positive, or eventually turned into a reusable custom risk rule. The schema supports both the category-level context and individually identified findings, including likelihood, impact, severity, affected assets, and data-breach probability.

The following example models an application-specific risk where public API clients can cause unbounded work through an expensive search request. This can be related to CWE-400, Uncontrolled Resource Consumption, but the actual issue is a design-specific combination of unrestricted query complexity and no request budget. It may not be covered by a built-in rule.

```yaml
individual_risk_categories:
  unbounded-search-query-cost:
    id: unbounded-search-query-cost
    description: >
      Public API requests can trigger expensive search operations without limits
      on query complexity, pagination depth, or request rate.
    impact: >
      Attackers could exhaust application and database resources, causing slow
      responses or an outage for legitimate users.
    asvs: ""
    cheat_sheet: ""
    action: >
      Add server-side query limits, pagination limits, timeouts, and rate limits
      before exposing the search endpoint to public clients.
    mitigation: >
      Enforce maximum result sizes and query complexity, apply rate limiting, and
      monitor for abnormal request patterns.
    check: >
      Test large pagination values, repeated requests, and expensive search
      combinations while monitoring application and database resource use.
    function: architecture
    stride: denial-of-service
    detection_logic: >
      Identified during architecture review. This is not currently detected by a
      built-in Threagile rule because query cost and request limits are not
      modeled as standard asset properties.
    risk_assessment: >
      The public search endpoint can be repeatedly invoked by unauthenticated
      clients and may execute costly queries against the backend datastore.
    false_positives: >
      This finding does not apply if the endpoint enforces effective server-side
      request budgets, rate limits, and query execution limits.
    model_failure_possible_reason: false
    cwe: 400
    risks_identified:
      public-search-endpoint:
        severity: high
        exploitation_likelihood: likely
        exploitation_impact: high
        data_breach_probability: improbable
        data_breach_technical_assets:
          - python-http-service
          - application-database
        most_relevant_data_asset: ""
        most_relevant_technical_asset: python-http-service
        most_relevant_communication_link: public-clients>public-search-api-request
        most_relevant_trust_boundary: internet
        most_relevant_shared_runtime: ""
```

Hopefully this demonstrates the usefulness of threat modeling with valid examples of risks, accepted risks, and mitigated risks.

[Using Optional Business and DevOps Fields](link_to_next_branch)