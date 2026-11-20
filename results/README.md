# Results

CSV files produced by `experiments/run_all.sh`.

* `correctness.csv`: 60 trials per dimension; LEAT and local decryption successes, worst noise relative to q/4, negative tests rejected.
* `timing_*.csv`: wall-clock medians (ms). **Reference run on a shared two-core cloud container, one thread.** Absolute values vary by machine; regenerate on your own hardware before quoting them.
* Analytic outputs (sizes, core-SVP bits, projections) are deterministic.
