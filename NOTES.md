# Open Questions And Follow-Up Items

This file captures the open questions and follow-up items that came out of the public-copy alignment pass.

## Open Questions

1. **How should UniFi support be described publicly right now?**
   The repo contains connector groundwork and early UniFi code, but the public wording still depends on whether you want to call that `experimental`, `early support`, or keep it framed as `in progress`.

2. **Do you want to keep `MahdiHedhli/vedetta` as the public repo identity while code modules still use `github.com/vedetta-network/...`?**
   The public URLs now point to the active GitHub repo, but the Go module path and some technical contributor docs still use the older namespace. That is fine short-term, but it is still an identity mismatch worth deciding on deliberately.

3. **How public do you want to be about the current alpha install shape?**
   The updated copy is honest about Docker, a native sensor, and elevated local access. If you want a sharper positioning line for the site, the next decision is whether to lean more toward `homelab/security practitioner alpha` or `small business early access`.

4. **When should the future community threat-network story become a first-class public message?**
   Right now it is intentionally framed as optional and future-facing. That should probably stay true until telemetry, batching, privacy controls, and the backend path are all more mature.

## Follow-Up Items

- **Finish end-to-end sensor authentication hardening.**
  Core can mint sensor tokens during registration, but the current sensor flow does not yet consume that trust path end to end.

- **Decide whether to unify repo/module naming.**
  If you want to fully standardize on `MahdiHedhli/vedetta`, that will require a careful Go module/import-path update across the repo.

- **Promote router/firewall coverage from code groundwork to documented support.**
  The next messaging upgrade should happen only after at least one connector path is clearly documented, testable, and supportable.

- **Revisit the public install story after the next setup pass.**
  Once install and onboarding improve, the homepage and README can be tightened again without overselling ease.
