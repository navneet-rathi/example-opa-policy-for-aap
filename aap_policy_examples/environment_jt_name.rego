package aap_policy_examples

import rego.v1

default allow = false

# List of allowed environment prefixes
allowed_environments := {
  "dev",
  "qa",
  "uat",
  "prod"
}

# Extract job template name
job_name := lower(input.job_template.name)

################################
# Allow rule
################################
allow if {
  some env
  env := allowed_environments[_]
  startswith(job_name, sprintf("%s-", [env]))
}

################################
# Deny rule
################################
deny[msg] if {
  not allow
  msg := sprintf(
    "Job template name '%s' must start with an environment name (%v). Example: prod-my-job",
    [input.job_template.name, allowed_environments]
  )
}
