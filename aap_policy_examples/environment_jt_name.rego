package aap_policy_examples

import rego.v1

################################
# Default response
################################
default jobt_naming_validation := {
    "allowed": true,
    "violations": [],
}

################################
# Allowed environment prefixes
################################
allowed_environments := {
    "dev",
    "qa",
    "uat",
    "prod",
}

################################
# Validation rule
################################
jobt_naming_validation := result if {
    # Extract job template name
    jt_name := lower(object.get(input, ["job_template", "name"], ""))

    # Job template does NOT start with any allowed environment
    not valid_environment_prefix(jt_name)

    result := {
        "allowed": false,
        "violations": [
            sprintf(
                "Job template name '%s' must start with an environment prefix (%v). Example: prod-my-job",
                [jt_name, allowed_environments]
            )
        ],
    }
}

################################
# Helper rule
################################
valid_environment_prefix(jt_name) if {
    some env in allowed_environments
    startswith(jt_name, sprintf("%s-", [env]))
}
