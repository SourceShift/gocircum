# TODO Tracker

This document tracks all `TODO` comments in the `gocircum` codebase. As of the last update, all identified TODOs have been resolved.

| File Location | Line Number | TODO Description | Category | Status | Issue Reference |
|---|---|---|---|---|---|
| `.github/workflows/main.yml` | 47 | Add a 'release' job that triggers on tags, builds all artifacts | Improvement | Resolved | #TODO-1 |
| `mobile/bridge/bridge.go` | 14 | Need a way to load configs. For now, they are hardcoded. | Improvement | Resolved | #TODO-2 |
| `core/ranker/ranker.go` | 25 | Add a cache for results to avoid re-testing. | Improvement | Resolved | #TODO-3 |
| `core/transport/middleware.go` | 131 | Implement ThrottlingMiddleware for rate limiting. | Improvement | Resolved | #TODO-4 |
| `core/transport/transport.go` | 23 | Expand with common options like timeouts. | Improvement | Resolved | #TODO-5 |
| `core/transport/transport.go` | 29 | Define specific transport-related error types here. | Improvement | Resolved | #TODO-6 | 