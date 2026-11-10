# AuthzBugs-50 - results

| metric | value |
|---|---|
| detection rate | **100%** (50/50) |
| false positives on patched apps | **0** / 5 apps |
| unexpected findings on buggy apps | 0 |
| regression tests valid | **100%** (290 reproduce, 290 blocked after the fix) |

| law | expected | detected |
|---|---|---|
| L1 (confused_identity) | 10 | 10 |
| L2 (idor_read) | 10 | 10 |
| L3 (idor_write) | 10 | 10 |
| L4 (mass_assignment) | 10 | 10 |
| L5 (race) | 10 | 10 |

## Applications

| application | expected | detected | missing | unexpected |
|---|---|---|---|---|
| authzbugs-50-00-idor_read | L2 | L2 | - | - |
| authzbugs-50-01-idor_write | L3 | L3 | - | - |
| authzbugs-50-02-mass_assignment | L4 | L4 | - | - |
| authzbugs-50-03-race | L5 | L5 | - | - |
| authzbugs-50-04-confused_identity | L1 | L1 | - | - |
| authzbugs-50-05-idor_read | L2 | L2 | - | - |
| authzbugs-50-06-idor_write | L3 | L3 | - | - |
| authzbugs-50-07-mass_assignment | L4 | L4 | - | - |
| authzbugs-50-08-race | L5 | L5 | - | - |
| authzbugs-50-09-confused_identity | L1 | L1 | - | - |
| authzbugs-50-10-idor_read | L2 | L2 | - | - |
| authzbugs-50-11-idor_write | L3 | L3 | - | - |
| authzbugs-50-12-mass_assignment | L4 | L4 | - | - |
| authzbugs-50-13-race | L5 | L5 | - | - |
| authzbugs-50-14-confused_identity | L1 | L1 | - | - |
| authzbugs-50-15-idor_read | L2 | L2 | - | - |
| authzbugs-50-16-idor_write | L3 | L3 | - | - |
| authzbugs-50-17-mass_assignment | L4 | L4 | - | - |
| authzbugs-50-18-race | L5 | L5 | - | - |
| authzbugs-50-19-confused_identity | L1 | L1 | - | - |
| authzbugs-50-20-idor_read | L2 | L2 | - | - |
| authzbugs-50-21-idor_write | L3 | L3 | - | - |
| authzbugs-50-22-mass_assignment | L4 | L4 | - | - |
| authzbugs-50-23-race | L5 | L5 | - | - |
| authzbugs-50-24-confused_identity | L1 | L1 | - | - |
| authzbugs-50-25-idor_read | L2 | L2 | - | - |
| authzbugs-50-26-idor_write | L3 | L3 | - | - |
| authzbugs-50-27-mass_assignment | L4 | L4 | - | - |
| authzbugs-50-28-race | L5 | L5 | - | - |
| authzbugs-50-29-confused_identity | L1 | L1 | - | - |
| authzbugs-50-30-idor_read | L2 | L2 | - | - |
| authzbugs-50-31-idor_write | L3 | L3 | - | - |
| authzbugs-50-32-mass_assignment | L4 | L4 | - | - |
| authzbugs-50-33-race | L5 | L5 | - | - |
| authzbugs-50-34-confused_identity | L1 | L1 | - | - |
| authzbugs-50-35-idor_read | L2 | L2 | - | - |
| authzbugs-50-36-idor_write | L3 | L3 | - | - |
| authzbugs-50-37-mass_assignment | L4 | L4 | - | - |
| authzbugs-50-38-race | L5 | L5 | - | - |
| authzbugs-50-39-confused_identity | L1 | L1 | - | - |
| authzbugs-50-40-idor_read | L2 | L2 | - | - |
| authzbugs-50-41-idor_write | L3 | L3 | - | - |
| authzbugs-50-42-mass_assignment | L4 | L4 | - | - |
| authzbugs-50-43-race | L5 | L5 | - | - |
| authzbugs-50-44-confused_identity | L1 | L1 | - | - |
| authzbugs-50-45-idor_read | L2 | L2 | - | - |
| authzbugs-50-46-idor_write | L3 | L3 | - | - |
| authzbugs-50-47-mass_assignment | L4 | L4 | - | - |
| authzbugs-50-48-race | L5 | L5 | - | - |
| authzbugs-50-49-confused_identity | L1 | L1 | - | - |