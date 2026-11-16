import statistics
import time

from dlp.dlp_engine import DLPEngine


RUNS = 20

PII_SAMPLES = {
    "email": "Contact john.doe@company.com for details.",
}

def make_sample(size, with_pii):
    if not with_pii:
        return "A" * size

    pii = PII_SAMPLES["email"]
    return ("A" * (size - len(pii))) + pii


SCENARIOS = {
    "short_clean": make_sample(50, False),
    "short_with_pii": make_sample(50, True),
    "medium_clean": make_sample(500, False),
    "medium_with_pii": make_sample(500, True),
    "large_clean": make_sample(5000, False),
    "large_with_pii": make_sample(5000, True),
}


def profile(engine, text):
    timings = []

    for _ in range(RUNS):
        start = time.perf_counter()
        engine.redact(text)
        elapsed = (time.perf_counter() - start) * 1000
        timings.append(elapsed)

    return {
        "mean": statistics.mean(timings),
        "median": statistics.median(timings),
        "min": min(timings),
        "max": max(timings),
    }


def main():
    engine = DLPEngine()

    # Warm up the NLP pipeline before measuring.
    engine.redact("Warm up with john@example.com")

    print("\nDAY 8 — OPTIMIZED LATENCY PROFILE (PRE-FILTER ENABLED)")
    print(f"Runs per scenario: {RUNS}")
    print("-" * 65)

    for name, text in SCENARIOS.items():
        result = profile(engine, text)

        print(f"\n{name} ({len(text)} characters)")
        print(f"  Mean:   {result['mean']:.3f} ms")
        print(f"  Median: {result['median']:.3f} ms")
        print(f"  Min:    {result['min']:.3f} ms")
        print(f"  Max:    {result['max']:.3f} ms")


if __name__ == "__main__":
    main()
