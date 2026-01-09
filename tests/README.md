# Test Suite

This folder contains a comprehensive test suite to exercise the tunl binary locally.

## Prerequisites
- Python 3 installed
- curl and nc (netcat) installed
- Optional: IPv6 loopback available (`::1`) for IPv6 tests

## What is covered
- Quick forward mode (`tunl -f`) for IPv4 and IPv6
- Config-driven serve mode (`tunl serve -C ...`) with rules
- Control interface commands (STATUS, RULES, HEALTH)
- Help and version output
- Check command functionality
- DNS command (cloudflare and cf alias)
- Invalid argument handling
- Config parsing (empty and multi-rule)

The following tests are defined but currently skipped (require more complex setup):
- Load balancing (round-robin, least-connections)
- Metrics endpoint (Prometheus format)
- Connection limits

## Running

```bash
./tests/run.sh
```

The runner will:
1. Build `bin/tunl` if missing.
2. Start temporary HTTP backends on various ports.
3. Test forward mode, config-based serve, control interface, and more.
4. Report pass/fail/skip status for each test.
5. Clean up all background processes.

Logs are written to `tests/logs/` for inspection.

## Test Output

The test suite uses colored output:
- 🟢 `[PASS]` - Test passed
- 🔴 `[FAIL]` - Test failed (with reason)
- 🟡 `[SKIP]` - Test skipped (e.g., IPv6 not available)

## Extending
- Add test fixtures under `tests/fixtures/`
- Add new test functions following the pattern `test_*()` in `tests/run.sh`
- Keep tests self-contained: start any helper services inside the test and they'll be cleaned up via the shared trap

## Troubleshooting

If tests hang:
```bash
pkill -9 -f tunl
pkill -9 -f python3
```

Check test logs:
```bash
cat tests/logs/*.log
```
