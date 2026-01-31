# Agent workspace: core
> **Project**: core

This folder contains agent-facing context, tasks, workflows, and planning artifacts for this submodule.

## Current State
Protocol kernel and shared primitives. Canonical encoding and security invariants are defined here or delegated to contracts artifacts. Focus is on correctness, determinism, and minimal coupling.

## Expected State
Stable kernel with strict interfaces and replaceable adapters. Performance-sensitive work is isolated and well tested.

## Behavior
Provides core protocol utilities and abstractions used by services and SDKs, without deep-linking across repos. Acts as a coordination point for kernel-level behavior.

## How to work here
- Run/tests:
- Local dev:
- CI notes:

## Interfaces and dependencies
- Owned APIs/contracts:
- Depends on:
- Data stores/events (if any):

## Global context
See `.agent/context.md` for monorepo-wide invariants and architecture.
