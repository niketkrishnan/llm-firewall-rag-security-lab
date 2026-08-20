# Threat Model

## Protected capability

This project addresses prompt-injection defense, untrusted-context isolation, sensitive-data controls, output inspection, and bounded tool authorization.

## In-scope threats

The main in-scope threats are direct and indirect prompt injection, sensitive-data leakage, unsafe output, and excessive tool authority.

## Trust boundaries

Inputs are untrusted telemetry, configuration, dependency metadata, identity
events, or application text depending on the project. The analysis layer is
read-only in demo mode. No external system is scanned or modified.

## Out of scope

Production access, credential collection, unrestricted tool execution, active
exploitation, and unauthorized data collection are out of scope.
