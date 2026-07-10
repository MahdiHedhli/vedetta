# SNR simulation tool

Generates synthetic DNS events across risk tiers (false-positive / mid-warning /
high-threat / mixed) to validate Vedetta's signal-to-noise scoring. Dev/test only.

The compiled binary is **not** committed (it is a ~10 MB platform-specific ELF).
Build it from source when you need it:

```sh
cd scripts/simulate
go build -o simulate .        # produces ./simulate (gitignored)
# or just run it directly:
go run . -count 100 -scenario mixed
```

Scenarios: `false_positive`, `mid_warning`, `high_threat`, `mixed`. See the doc
comment at the top of `main.go` for the full flag list.
