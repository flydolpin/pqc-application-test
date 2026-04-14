# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Post-quantum cryptography (PQC) TLS testing framework. Tests certificate and TLS protocol modifications with PQC algorithms, measuring RTT latency and packet loss under real network conditions.

## Architecture

- **Language**: C/C++
- **PQC algorithms must be modular and swappable** — design with an abstraction layer so different PQC libraries (OQS, CIRCL, etc.) can be plugged in without changing the TLS or testing logic.
- TLS client/server implementation for real-network communication
- Benchmarking suite for RTT latency and packet loss measurement

## Guidelines

- Explain tradeoffs when proposing architectural decisions or refactoring approaches.
- When adding a new PQC algorithm integration, implement it through the existing module interface rather than hard-coding.
