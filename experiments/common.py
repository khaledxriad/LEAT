import csv
import os
import statistics
import time

RESULTS = os.path.join(os.path.dirname(__file__), "..", "results")


def median_time(fn, reps=5, warmup=1):
    """Median wall-clock time of fn() in seconds."""
    for _ in range(warmup):
        fn()
    xs = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        xs.append(time.perf_counter() - t0)
    return statistics.median(xs)


def write_csv(name, header, rows):
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, name)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print("wrote", os.path.normpath(path))


def read_csv(name):
    with open(os.path.join(RESULTS, name)) as f:
        return list(csv.DictReader(f))
