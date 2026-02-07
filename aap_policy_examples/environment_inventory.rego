package inventory.naming

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

# Allow inventory if name starts with a valid environment prefix
allow {
  some env
  env := allowed_environments[_]
  startswith(inventory_name, sprintf("%s-", [env]))
}

# Deny message if naming convention is violated
deny[msg] {
  not allow
  msg := sprintf(
    "Inventory name '%s' must start with an environment name (%v). Example: prod-linux-servers",
    [input.inventory.name, allowed_environments]
  )
}
