# Architecture

```text
a versioned local attack-and-benign corpus mapped to OWASP GenAI security categories -> normalized input -> security analysis -> explainable result
                                                |
                                         tests and evaluation
```

The repository keeps the core analysis logic independent from the command-line
evaluation entry point. This supports deterministic unit tests and makes it
possible to add an API or dashboard without changing the security boundary.
