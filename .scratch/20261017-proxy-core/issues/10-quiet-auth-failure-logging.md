# 10: Quiet auth-failure logging

**What to build:** Authentication challenges are routine for iOS clients and background daemons
that retry without credentials first, so they move off the default log output. The count stays
visible as the `homeproxy_auth_failures_total` metric.

**Blocked by:** 05 (operator visibility)

**Status:** done

- [x] auth failures are logged at debug level and do not appear at the default info level
- [x] the debug line still carries the remote address and the attempted name, and no credentials
- [x] the end-to-end log test enables debug logging to keep asserting that line
- [x] `homeproxy_auth_failures_total` still counts every rejected attempt
