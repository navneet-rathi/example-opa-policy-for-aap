package aap_policy_examples

import rego.v1

# Allowed environment prefixes
allowed_environments := {
  "dev",
  "qa",
  "uat",
  "prod"
}

inventory_name := lower(input.inventory.name)

################################
# Helper rule
################################
valid_inventory_name if {
  some env in allowed_environments
  startswith(inventory_name, sprintf("%s-", [env]))
}

################################
# Deny rule only
################################
deny[msg] if {
  not valid_inventory_name
  msg := sprintf(
    "Inventory name '%s' must start with an environment name (%v). Example: prod-linux-servers",
    [input.inventory.name, allowed_environments]
  )
}
