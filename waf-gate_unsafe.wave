#! VULNERABLE waf-gate — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant filterReq confidence 70

let raw = fetch<web>
privileged { filterReq(raw) }  # tainted -> tool: REJECTED
