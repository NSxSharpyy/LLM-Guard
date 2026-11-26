# Day 18 — Redis Memory Footprint and Garbage Collection Report

## 1. Objective

Evaluate Redis memory usage under a simulated workload of 10,000 sessions, verify automatic cleanup of expired session mappings, and assess memory capacity.

## 2. Redis Configuration

| Setting | Value |
|---|---|
| Redis image | `redis:7-alpine` |
| Host | `127.0.0.1` |
| Host port | `6380` |
| Maximum memory | 256 MiB |
| Eviction policy | `volatile-lru` |
| Persistence | Append-only file (AOF) |
| Data volume | `llm_guard_redis_day18_data` |

The configuration was verified after restarting the Redis container. The settings remained:

- `maxmemory-policy`: `volatile-lru`
- `maxmemory`: `268435456` bytes

This confirms that the configuration is applied through Docker Compose startup settings rather than relying on temporary runtime configuration.

## 3. Simulation Workload

The simulation used synthetic data and generated:

- 10,000 sessions
- 39,999 mappings
- 60-second TTL per session mapping
- 65-second expiration wait
- Approximately 7.15 seconds to load the workload

The simulation used Redis database 14.

## 4. Memory Measurements

| Measurement | Used memory | Database keys |
|---|---:|---:|
| Baseline | 1,525,528 bytes (1.45 MiB) | 0 |
| After loading 10,000 sessions | 15,656,560 bytes (14.93 MiB) | 49,999 |
| After TTL expiration | 1,510,752 bytes (1.44 MiB) | 0 |

Memory increased by 14,131,032 bytes during the workload.

Average measured memory increase:

**1,413.1 bytes per session**

After TTL expiration, the database contained zero keys and memory usage returned close to its baseline.

## 5. Capacity Estimates

Based on the measured average memory increase per session:

| Estimated sessions | Additional estimated memory |
|---|---:|
| 100,000 | 141,310,320 bytes (approximately 134.76 MiB) |
| 1,000,000 | 1,413,103,200 bytes (approximately 1.32 GiB) |

These are workload-specific linear extrapolations, not measured production capacities. Actual capacity depends on mapping sizes, Redis overhead, concurrent activity, allocator fragmentation, and other workloads.

## 6. TTL Cleanup and Eviction Policy

Redis uses `volatile-lru`.

This policy evicts the least recently used keys among keys that have an expiration set when Redis needs to reclaim memory.

Important distinction:

- `volatile-lru` does not select keys simply because they are closest to expiration.
- Keys without TTL are not eligible for this eviction policy.
- Session mappings should retain their configured TTL.
- Under memory pressure, Redis may evict a TTL-protected session before its natural expiration.

The simulation confirmed that all 49,999 workload keys expired and that zero namespaced keys remained after the TTL wait.

## 7. Restart Persistence Verification

After restarting the `redis-day18` Docker Compose service, the following settings were checked inside the container:

```bash
docker exec llm-guard-redis-day18 redis-cli CONFIG GET maxmemory-policy
docker exec llm-guard-redis-day18 redis-cli CONFIG GET maxmemory
```

Verified results:

```text
maxmemory-policy
volatile-lru

maxmemory
268435456
```

Both settings survived the container restart.

## 8. Conclusion

The 10,000-session simulation completed successfully. Redis memory usage increased during the workload and returned close to its initial level after TTL expiration. The database contained zero remaining keys after cleanup.

The measured workload showed an average memory increase of approximately 1,413 bytes per session. The results provide a useful initial capacity estimate, but production sizing should include additional headroom and testing under realistic concurrent workloads.

**Day 18 result: PASS — memory simulation, TTL cleanup, configuration verification, and restart persistence checks completed.**
