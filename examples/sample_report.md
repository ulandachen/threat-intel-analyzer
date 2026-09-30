# Threat Intelligence Analysis Report

**Unique indicators analyzed:** 5

## Risk Summary

- **Critical**: 1
- **High**: 2
- **Medium**: 1
- **Low**: 1

## Prioritized Indicators

| Score | Risk | Type | Indicator | Confidence | Source | Age | MITRE ATT&CK |
|---:|---|---|---|---:|---|---:|---|
| 99 | Critical | ip | `198.51.100.24` | 96% | demo-feed | 2d | T1071, T1105 |
| 78 | High | domain | `malicious-login.example` | 90% | demo-feed | 3d | T1566, T1056 |
| 74 | High | url | `hxxps://update-check.example/payload` | 82% | demo-feed | 9d | T1105 |
| 51 | Medium | hash | `44d88612fea8a8f36de82e1278abb02f` | 75% | demo-feed | 31d | T1204 |
| 24 | Low | ip | `203.0.113.77` | 45% | demo-feed | 111d | T1595 |

## MITRE ATT&CK Coverage

- **T1105**: 2 indicator(s)
- **T1056**: 1 indicator(s)
- **T1071**: 1 indicator(s)
- **T1204**: 1 indicator(s)
- **T1566**: 1 indicator(s)
- **T1595**: 1 indicator(s)

> Risk scores are a prioritization aid for this demo project and should not be treated as a replacement for analyst validation.
