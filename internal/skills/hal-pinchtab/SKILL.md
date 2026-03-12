---
name: hal-pinchtab
description: Verify web UI behavior with Pinchtab and recover from common local Pinchtab failures. Use when browser verification, page navigation, screenshots, or Pinchtab debugging is needed in Hal workflows.
---

# Pinchtab Browser Verification

Use this skill only when a dev server is already running. If no server is running, skip browser verification and rely on non-browser checks.

## Workflow

1. Confirm the target app is serving locally before opening a browser.
2. Check Pinchtab readiness with `pinchtab health` and `pinchtab instances`.
3. Prefer reusing a healthy instance. Prefer `--mode headless` for repeated automation; use `--mode headed` only when visual debugging matters.
4. Run the browser verification needed for the task.
5. Retry Pinchtab up to 3 times for transient failures.
6. If Pinchtab is unavailable or recovery fails after 3 attempts, stop browser verification and report the skip reason.

## Mental Model

Pinchtab has 3 layers:

1. Dashboard server on `127.0.0.1:9867`
   `pinchtab health` only checks this layer.
2. Instance or bridge process on `127.0.0.1:9868`
   This layer handles `/navigate`, `/tabs`, and tab lifecycle.
3. Chrome CDP endpoint on `127.0.0.1:9869`
   This is the underlying browser control layer.

A healthy dashboard does not guarantee tab creation or navigation will work.

## Failure Meanings

- `503: no running instances`
  The dashboard is up, but there is no active Pinchtab instance.
- `500: new tab: create target: context deadline exceeded`
  CDP tab creation failed before navigation started. The instance is usually stuck.
- Logs such as `get targets: context deadline exceeded`
  Treat this as a bad CDP state and restart the instance.

In headed mode, manually closing the managed Chrome window or last tab often breaks the instance. Treat that instance as dead and restart it.

## Recovery Runbook

```bash
pinchtab instances
pinchtab instance stop <instance-id>
pinchtab instance start --profileId <profile-id> --mode headed
pinchtab nav https://google.com
```

When you need evidence before restarting, capture:

```bash
pinchtab instance logs <instance-id>
```

## Operational Notes

- `/navigate` creates a new tab when no `tabId` is provided.
- `pinchtab health` is not enough for readiness. Pair it with `pinchtab instances` and a real navigation or tab command.
- Different terminals hit the same local Pinchtab server, so shell choice does not change instance state.
- In headed mode, do not close the managed browser manually.
- If `pinchtab profiles` prints a profile and then warns about `No profiles available`, treat that as a Pinchtab CLI parsing bug unless the profile is actually missing.
