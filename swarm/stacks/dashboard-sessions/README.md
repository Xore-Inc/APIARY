# Dashboard session store (#3592)

This is the current dashboard's memory-only Valkey configuration packaged as
an Arcane GitOps Swarm stack. It has one replica on the non-sensor manager,
no published port, no host mount, and an encrypted internal overlay with the
fleet's 1310 MTU. Its image is the same digest as the current Compose service.

This stack is only preparation for phase 5. The live dashboard continues to
use its Compose `oidc-sessions` container. Deploying this isolated stack does
not move sessions; changing the dashboard's Redis URL would invalidate
existing sessions, so the route/session cutover must be coordinated with the
dashboard deployment and its rollback plan. A future dashboard Swarm stack
can join the external network `dashboard-sessions_session` and use
`redis://dashboard-sessions_valkey:6379/0`.

Before a production cutover, complete the backend API/worker split (#3575),
private authenticated cross-host transport (#3577), host-local data/control
paths (#3582), and dashboard portability (Xore/apiary-dashboard#243). Keep
the current Compose Valkey running until that cutover is verified.
