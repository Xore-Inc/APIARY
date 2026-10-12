# Phase-4 internal canary (#3591)

This is an isolated HTTP service for proving the Arcane GitOps Swarm path.
It is **not** the existing-service migration required to close #3591. It has
no public route, host mount, or application dependency.

The stack has two replicas on nodes labelled `role=manager`, an encrypted
overlay with MTU 1310, a versioned external config, health checks, and
automatic update rollback. Homeserver normally has Swarm availability
`Pause` (#3583), so both replicas normally run on precision. To verify
cross-manager placement, temporarily set homeserver `Active`, scale the
canary to zero and back to two, then restore it by draining homeserver and
setting it back to `Pause`. Never leave the homeserver active after the test.

Verified on 2026-10-12:

- `stackctl.py ensure canary --branch feat/3591-swarm-canary` created the
  Arcane `swarm_stack` sync and converged at 2/2.
- With homeserver temporarily active, tasks landed one per manager and the
  homeserver task fetched the v2 page from the precision task's overlay IP.
- Draining precision moved both tasks to homeserver. Restoring precision,
  draining homeserver, then setting homeserver to `Pause` restored 2/2 on
  precision.
- Arcane deployed config `canary_page_v2` as a rolling update. A temporary
  direct service update with a failing health command triggered
  `rollback_completed`; the service returned to 2/2 and served the v2 page.
- The first overlay exposed MTU 1450; recreating the stack with an explicit
  1310 overlay MTU gave each container MTU 1260. Cross-node HTTP succeeded
  after that recreation.

The temporary GitOps sync tracks the feature branch with `autoSync=false`.
After merging, run `ops/swarm/stackctl.py ensure canary --branch main` and
`ops/swarm/stackctl.py deploy canary`, then verify 2/2 and the v2 page.
