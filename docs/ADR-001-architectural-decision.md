# ADR-001: Private DNS Topologies: Eliminating Split-Brain Resolution Contention in Multi-Spoke Landing Zones

## Status
Accepted

## Service Owner & Sign-Off Authority
Principal Azure Core Networking & Hybrid Connectivity Architect

## Dominant Artefact
Distributed Private DNS Architecture Blueprint & Resolution Test Suite

## Decision & Refusal Boundary
All production state mutations must pass deterministic pre-flight policy evaluation in `src/Test-PrivateDnsSplitBrainGuard.ps1` and satisfy the 16-test Pester verification contract in `tests/Boundary-Verification.Tests.ps1` before execution.
