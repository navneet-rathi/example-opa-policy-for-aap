package aap.project.execution

default allow = false

################################
# Time calculations
################################

# Current time in nanoseconds (UTC)
now_ns := time.now_ns()

# Convert to seconds
now_seconds := now_ns / 1000000000

# Convert UTC → IST (+5:30 = 19800 seconds)
ist_seconds := now_seconds + 19800

# Hour in IST (0–23)
ist_hour := (ist_seconds / 3600) % 24

################################
# Access rules
################################

# Rule: execution allowed only for non-superuser
non_superuser {
  input.user.is_superuser == false
}

# Rule: execution allowed only between 12:00 IST and 06:00 IST
allowed_time {
  ist_hour >= 12
}

allowed_time {
  ist_hour < 6
}

################################
# Final allow rule
################################

allow {
  non_superuser
  allowed_time
}

################################
# Deny messages
################################

deny[msg] {
  input.user.is_superuser == true
  msg := "Project execution is not allowed for superusers."
}

deny[msg] {
  not allowed_time
  msg := sprintf(
    "Project execution is allowed only between 12:00 IST and 06:00 IST. Current IST hour: %d",
    [ist_hour]
  )
}
