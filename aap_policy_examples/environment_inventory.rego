package aap_policy_examples

import rego.v1

default allow = false

# Allowed environment prefixes
allowed_environments := {
  "dev",
  "qa",
  "uat",
  "prod"
}

# Normalize inventory name to lowercase
inventory_name := lower(input.inventory.name)

################################
# Allow rule
################################
allow if {
  some env
  env := allowed_environments[_]
  startswith(inventory_name, sprintf("%s-", [env]))
}

################################
# Deny rule
################################
deny[msg] if {
  not allow
  msg := sprintf(
    "Inventory name '%s' must start with an environment name (%v). Example: prod-linux-servers",
    [input.inventory.name, allowed_environments]
  )
}
