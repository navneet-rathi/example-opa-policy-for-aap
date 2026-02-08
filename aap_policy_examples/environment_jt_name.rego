package aap_policy_examples

import rego.v1

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
# Helper rule: valid job template name
################################
valid_job_template_name if {
  some env in allowed_environments
  startswith(job_name, sprintf("%s-", [env]))
}

################################
# Deny rule only
################################
deny[msg] if {
  not valid_job_template_name
  msg := sprintf(
    "Job template name '%s' must start with an environment name (%v). Example: prod-my-job",
    [input.job_template.name, allowed_environments]
  )
}
