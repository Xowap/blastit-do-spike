# blastit-do-spike

Throwaway probe for the blastit architecture (§11 validation spikes S1–S6) on
DigitalOcean App Platform (gVisor). Stdlib-only Python; every probe runs in a
forked child, often after dropping to an arbitrary uid.

* `GET /` — summary
* `GET /full` — full report
* `GET /rerun` — re-run all probes, then return the full report

Local run: `docker build -t spike . && docker run --rm spike python3 /app/probe.py --once`
