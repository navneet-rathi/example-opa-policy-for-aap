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
# Helper rule: valid inventory name
################################
valid_inventory_name if {
  some env
  env := allowed_environments[_]
  startswith(inventory_name, sprintf("%s-", [env]))
}

################################
# Allow rule
################################
allow if {
  valid_inventory_name
}

################################
# Deny rule
################################
deny[msg] if {
  not valid_inventory_name
  msg := sprintf(
    "Inventory name '%s' must start with an environment name (%v). Example: prod-linux-servers",
    [input.inventory.name, allowed_environments]
  )
}
