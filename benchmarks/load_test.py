import asyncio
import json
import math
import os
import time
from datetime import datetime, timezone
from typing import Any

import httpx

PROXY_URL = os.getenv("PROXY_URL", "http://127.0.0.1:8000")
CONCURRENCY = int(os.getenv("BENCH_CONCURRENCY", "100"))
TOTAL_REQUESTS_PER_MODE = int(os.getenv("BENCH_REQUESTS", "500"))
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "baseline_metrics.json")


def calculate_percentile(sorted_data: list[float], percentile: float) -> float:
    if not sorted_data:
        return 0.0
    k = (len(sorted_data) - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return round(sorted_data[int(k)], 3)
    d0 = sorted_data[int(f)] * (c - k)
    d1 = sorted_data[int(c)] * (k - f)
    return round(d0 + d1, 3)


async def run_unary_worker(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    e2e_latencies: list[float],
    proxy_latencies: list[float],
    errors: list[str],
) -> None:
    payload = {
        "model": "mock-llama-3",
        "messages": [{"role": "user", "content": "Benchmark unary latency"}],
        "stream": False,
    }
    headers = {"X-Mock-Benchmark-Mode": "true"}

    async with semaphore:
        t_start = time.perf_counter()
        try:
            resp = await client.post("/v1/chat/completions", json=payload, headers=headers)
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            if resp.status_code == 200:
                e2e_latencies.append(elapsed_ms)
                if "x-proxy-latency-ms" in resp.headers:
                    proxy_latencies.append(float(resp.headers["x-proxy-latency-ms"]))
            else:
                errors.append(f"HTTP {resp.status_code}")
        except Exception as exc:
            errors.append(str(exc))


async def run_streaming_worker(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    ttft_latencies: list[float],
    proxy_ttft_latencies: list[float],
    total_latencies: list[float],
    errors: list[str],
) -> None:
    payload = {
        "model": "mock-llama-3",
        "messages": [{"role": "user", "content": "Benchmark SSE streaming latency"}],
        "stream": True,
    }
    headers = {"X-Mock-Benchmark-Mode": "true"}

    async with semaphore:
        t_start = time.perf_counter()
        first_chunk_ms: float | None = None
        try:
            async with client.stream(
                "POST", "/v1/chat/completions", json=payload, headers=headers
            ) as resp:
                if resp.status_code != 200:
                    errors.append(f"HTTP {resp.status_code}")
                    return

                if "x-proxy-ttft-ms" in resp.headers:
                    proxy_ttft_latencies.append(float(resp.headers["x-proxy-ttft-ms"]))

                # Drain stream completely so server closes cleanly without ClientDisconnect
                async for line in resp.aiter_lines():
                    if first_chunk_ms is None and line.strip():
                        first_chunk_ms = (time.perf_counter() - t_start) * 1000.0

            total_ms = (time.perf_counter() - t_start) * 1000.0
            if first_chunk_ms is not None:
                ttft_latencies.append(first_chunk_ms)
            total_latencies.append(total_ms)
        except Exception as exc:
            errors.append(str(exc))


async def benchmark_unary(client: httpx.AsyncClient, concurrency: int, total_requests: int) -> dict[str, Any]:
    semaphore = asyncio.Semaphore(concurrency)
    e2e_latencies: list[float] = []
    proxy_latencies: list[float] = []
    errors: list[str] = []

    warmup_tasks = [run_unary_worker(client, semaphore, [], [], []) for _ in range(10)]
    await asyncio.gather(*warmup_tasks)

    t0 = time.perf_counter()
    tasks = [
        run_unary_worker(client, semaphore, e2e_latencies, proxy_latencies, errors)
        for _ in range(total_requests)
    ]
    await asyncio.gather(*tasks)
    duration_sec = time.perf_counter() - t0

    sorted_e2e = sorted(e2e_latencies)
    sorted_proxy = sorted(proxy_latencies)
    error_rate = (len(errors) / total_requests) * 100.0

    return {
        "total_requests": total_requests,
        "concurrency": concurrency,
        "successful_requests": len(e2e_latencies),
        "failed_requests": len(errors),
        "error_rate_pct": round(error_rate, 3),
        "throughput_rps": round(len(e2e_latencies) / duration_sec, 2),
        "e2e_p50_ms": calculate_percentile(sorted_e2e, 50),
        "e2e_p90_ms": calculate_percentile(sorted_e2e, 90),
        "e2e_p99_ms": calculate_percentile(sorted_e2e, 99),
        "proxy_transit_p50_ms": calculate_percentile(sorted_proxy, 50),
        "proxy_transit_p90_ms": calculate_percentile(sorted_proxy, 90),
        "proxy_transit_p99_ms": calculate_percentile(sorted_proxy, 99),
    }


async def benchmark_streaming(client: httpx.AsyncClient, concurrency: int, total_requests: int) -> dict[str, Any]:
    semaphore = asyncio.Semaphore(concurrency)
    ttft_latencies: list[float] = []
    proxy_ttft_latencies: list[float] = []
    total_latencies: list[float] = []
    errors: list[str] = []

    t0 = time.perf_counter()
    tasks = [
        run_streaming_worker(
            client, semaphore, ttft_latencies, proxy_ttft_latencies, total_latencies, errors
        )
        for _ in range(total_requests)
    ]
    await asyncio.gather(*tasks)
    duration_sec = time.perf_counter() - t0

    sorted_ttft = sorted(ttft_latencies)
    sorted_proxy_ttft = sorted(proxy_ttft_latencies)
    sorted_total = sorted(total_latencies)
    error_rate = (len(errors) / total_requests) * 100.0

    return {
        "total_requests": total_requests,
        "concurrency": concurrency,
        "successful_streams": len(total_latencies),
        "failed_streams": len(errors),
        "error_rate_pct": round(error_rate, 3),
        "throughput_streams_per_sec": round(len(total_latencies) / duration_sec, 2),
        "e2e_ttft_p50_ms": calculate_percentile(sorted_ttft, 50),
        "e2e_ttft_p90_ms": calculate_percentile(sorted_ttft, 90),
        "e2e_ttft_p99_ms": calculate_percentile(sorted_ttft, 99),
        "proxy_ttft_p50_ms": calculate_percentile(sorted_proxy_ttft, 50),
        "proxy_ttft_p90_ms": calculate_percentile(sorted_proxy_ttft, 90),
        "proxy_ttft_p99_ms": calculate_percentile(sorted_proxy_ttft, 99),
        "stream_total_p99_ms": calculate_percentile(sorted_total, 99),
    }


async def main() -> None:
    limits = httpx.Limits(max_keepalive_connections=150, max_connections=500)
    timeout = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=10.0)

    print(f"\n🚀 Starting Day 5 Baseline Load Benchmark against {PROXY_URL}")
    print(f"   Concurrency: {CONCURRENCY} virtual users | Requests per mode: {TOTAL_REQUESTS_PER_MODE}\n")

    async with httpx.AsyncClient(base_url=PROXY_URL, limits=limits, timeout=timeout) as client:
        health = await client.get("/healthz")
        if health.status_code != 200:
            raise RuntimeError("Proxy healthcheck failed. Ensure ports 8000 and 8001 are running.")

        print("▶️  Running Unary JSON Load Profile...")
        unary_stats = await benchmark_unary(client, CONCURRENCY, TOTAL_REQUESTS_PER_MODE)

        print("▶️  Running SSE Streaming Load Profile...")
        streaming_stats = await benchmark_streaming(client, CONCURRENCY, TOTAL_REQUESTS_PER_MODE)

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "proxy_target": PROXY_URL,
        "unary_baseline": unary_stats,
        "streaming_baseline": streaming_stats,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 68)
    print("📊 BASELINE LATENCY & THROUGHPUT SUMMARY")
    print("=" * 68)
    print(f"[Unary E2E]       p50: {unary_stats['e2e_p50_ms']} ms | p90: {unary_stats['e2e_p90_ms']} ms | p99: {unary_stats['e2e_p99_ms']} ms | Errors: {unary_stats['error_rate_pct']}% | RPS: {unary_stats['throughput_rps']}")
    print(f"[Unary Proxy]     p50: {unary_stats['proxy_transit_p50_ms']} ms | p90: {unary_stats['proxy_transit_p90_ms']} ms | p99: {unary_stats['proxy_transit_p99_ms']} ms")
    print(f"[SSE E2E TTFT]    p50: {streaming_stats['e2e_ttft_p50_ms']} ms | p90: {streaming_stats['e2e_ttft_p90_ms']} ms | p99: {streaming_stats['e2e_ttft_p99_ms']} ms | Errors: {streaming_stats['error_rate_pct']}% | RPS: {streaming_stats['throughput_streams_per_sec']}")
    print(f"[SSE Proxy TTFT]  p50: {streaming_stats['proxy_ttft_p50_ms']} ms | p90: {streaming_stats['proxy_ttft_p90_ms']} ms | p99: {streaming_stats['proxy_ttft_p99_ms']} ms")
    print("=" * 68)
    print(f"✅ Saved baseline metrics to: {OUTPUT_FILE}\n")


if __name__ == "__main__":
    asyncio.run(main())
