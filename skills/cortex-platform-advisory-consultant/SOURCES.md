<!--
SPDX-FileCopyrightText: GoCortexIO
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Sources

**Derived file. Do not hand-edit.** Regenerate with `python3 scripts/build_manifest.py`;
`--check` fails if it is out of date, and a test in `tests/` runs that check.

Every publisher whose material is represented in `corpus/observations/observations.jsonl`,
with the kind of source it is, how its records are cited, and how many there are. It is built
from the corpus rather than maintained beside it, so it cannot drift from what the bundle
actually holds.

The full sync record -- routes, pass logs, per-source backlogs and the decisions behind what
was taken and what was refused -- is maintainer-side and is not part of a shipped bundle.

**Citation and reuse.** A `public` source carries a real `where.url` a reader can open and its
own title. A `restricted` source is licensed intelligence: it carries no URL, its title is
abstracted to `<Publisher> commentary on <subject>`, its dates are month-precision at finest,
and no report identifier appears anywhere. `scripts/validate.py` enforces that on the records
and on this bundle's prose. Cite a restricted source as its title states it and no further.


## Totals

| | count |
|---|---|
| records | 1151 |
| distinct publishers | 106 |
| -- source_type `database` | 748 |
| -- source_type `government_advisory` | 180 |
| -- source_type `vendor_advisory` | 120 |
| -- source_type `vendor_research` | 81 |
| -- source_type `independent_research` | 15 |
| -- source_type `academic_research` | 3 |
| -- source_type `licensed_intel` | 3 |
| -- source_type `incident_report` | 1 |
| -- disclosure `public` | 1148 |
| -- disclosure `restricted` | 3 |

## Publishers

| publisher | source type | citation | records |
|---|---|---|---|
| CISA | database, government_advisory | public | 725 |
| Zero Day Initiative | vendor_advisory | public | 65 |
| NIST National Vulnerability Database | database | public | 44 |
| Fortinet PSIRT | vendor_advisory | public | 25 |
| CISA and FBI | government_advisory | public | 22 |
| Nokia PSIRT | vendor_advisory | public | 17 |
| Palo Alto Networks PSIRT | vendor_advisory | public | 13 |
| FBI and CISA | government_advisory | public | 12 |
| Sysdig | vendor_research | public | 12 |
| CISA, NSA, FBI and international partners | government_advisory | public | 10 |
| NSA, CISA and FBI | government_advisory | public | 10 |
| CISA, FBI and NSA | government_advisory | public | 9 |
| Cisco Talos | vendor_research | public | 8 |
| Datadog Security Labs | vendor_research | public | 8 |
| watchTowr Labs | independent_research | public | 8 |
| Horizon3.ai | independent_research, vendor_research | public | 7 |
| Unit 42 | vendor_research | public | 6 |
| CISA, FBI, Europol EC3 and NCSC-NL | government_advisory | public | 5 |
| Mandiant (Google Cloud) | vendor_research | public | 5 |
| Sysdig Threat Research Team | vendor_research | public | 5 |
| Zscaler ThreatLabz | vendor_research | public | 5 |
| ASD's ACSC, CISA, NSA, FBI and international partners | government_advisory | public | 4 |
| CISA, ACSC, NCSC-UK and FBI | government_advisory | public | 4 |
| CISA, NSA and FBI with international partners | government_advisory | public | 4 |
| Volexity | vendor_research | public | 4 |
| Check Point Research | vendor_research | public | 3 |
| CISA and Multi-State Information Sharing and Analysis Center | government_advisory | public | 3 |
| Elastic Security Labs | vendor_research | public | 3 |
| FBI, CISA and MS-ISAC | government_advisory | public | 3 |
| Forescout Vedere Labs | vendor_research | public | 3 |
| NSA and CISA | government_advisory | public | 3 |
| NSA, FBI, NCSC-UK and international partners | government_advisory | public | 3 |
| Okta Security | incident_report, vendor_research | public | 3 |
| Restricted detection library | licensed_intel | restricted | 3 |
| Wiz | vendor_research | public | 3 |
| Wiz Research | vendor_research | public | 3 |
| ASD's ACSC | government_advisory | public | 2 |
| Assetnote | independent_research | public | 2 |
| CISA, FBI and Department of Health and Human Services | government_advisory | public | 2 |
| CISA, FBI and Multi-State Information Sharing and Analysis Center | government_advisory | public | 2 |
| Cyber security authorities of Australia, Canada, New Zealand, the United Kingdom and the United States | government_advisory | public | 2 |
| FBI, CISA and Multi-State Information Sharing and Analysis Center | government_advisory | public | 2 |
| FBI, CISA, NSA and international partners | government_advisory | public | 2 |
| MITRE | independent_research | public | 2 |
| NSA, FBI, CISA, HHS and Republic of Korea agencies | government_advisory | public | 2 |
| Proofpoint | vendor_research | public | 2 |
| Unit 42 (Palo Alto Networks) | vendor_research | public | 2 |
| Australian Cyber Security Centre, CISA and NSA | government_advisory | public | 1 |
| CISA and Australian Cyber Security Centre | government_advisory | public | 1 |
| CISA and Department of the Treasury Financial Crimes Enforcement Network | government_advisory | public | 1 |
| CISA and international partners | government_advisory | public | 1 |
| CISA and NCSC-UK | government_advisory | public | 1 |
| CISA and Norwegian National Cyber Security Centre | government_advisory | public | 1 |
| CISA and United States Coast Guard | government_advisory | public | 1 |
| CISA and United States Coast Guard Cyber Command | government_advisory | public | 1 |
| CISA National Cybersecurity and Communications Integration Center | government_advisory | public | 1 |
| CISA, ACSC, CCCS, NZ NCSC, NCSC-UK, FBI and NSA | government_advisory | public | 1 |
| CISA, FBI and Cyber National Mission Force | government_advisory | public | 1 |
| CISA, FBI and MS-ISAC | government_advisory | public | 1 |
| CISA, FBI and US Cyber Command Cyber National Mission Force | government_advisory | public | 1 |
| CISA, FBI, ACSC and Australian Cyber Security Centre | government_advisory | public | 1 |
| CISA, FBI, EPA and NSA | government_advisory | public | 1 |
| CISA, FBI, HHS and MS-ISAC | government_advisory | public | 1 |
| CISA, FBI, MS-ISAC and Australian Cyber Security Centre | government_advisory | public | 1 |
| CISA, FBI, MS-ISAC and Canadian Centre for Cyber Security | government_advisory | public | 1 |
| CISA, FBI, MS-ISAC and international partners | government_advisory | public | 1 |
| CISA, FBI, NSA and international partners | government_advisory | public | 1 |
| CISA, FBI, NSA, Australian Cyber Security Centre and NCSC-UK | government_advisory | public | 1 |
| CISA, NSA and Multi-State Information Sharing and Analysis Center | government_advisory | public | 1 |
| CISA, NSA, FBI, ACSC, CCCS, NZ NCSC and NCSC-UK | government_advisory | public | 1 |
| CISA, NSA, FBI, Canadian Centre for Cyber Security, NCSC-NZ, Netherlands NCSC and NCSC-UK | government_advisory | public | 1 |
| CISA, US Department of the Treasury, FBI and US Cyber Command | government_advisory | public | 1 |
| Department of Energy, CISA, NSA and FBI | government_advisory | public | 1 |
| Fares, Gamage and Baudry | academic_research | public | 1 |
| FBI, CISA and ASD's ACSC | government_advisory | public | 1 |
| FBI, CISA and Australian Cyber Security Centre | government_advisory | public | 1 |
| FBI, CISA and Department of Health and Human Services | government_advisory | public | 1 |
| FBI, CISA and Department of the Treasury | government_advisory | public | 1 |
| FBI, CISA and HHS | government_advisory | public | 1 |
| FBI, CISA and US Department of Defense Cyber Crime Center | government_advisory | public | 1 |
| FBI, CISA and US Department of the Treasury | government_advisory | public | 1 |
| FBI, CISA, Department of the Treasury and Financial Crimes Enforcement Network | government_advisory | public | 1 |
| FBI, CISA, EPA and Multi-State Information Sharing and Analysis Center | government_advisory | public | 1 |
| FBI, CISA, HHS and MS-ISAC | government_advisory | public | 1 |
| FBI, CISA, MS-ISAC and HHS | government_advisory | public | 1 |
| FBI, CISA, NSA, ASD's ACSC and international partners | government_advisory | public | 1 |
| FBI, CISA, NSA, CNMF, Department of the Treasury, ACSC, CCCS and NCSC-UK | government_advisory | public | 1 |
| FBI, CISA, NSA, EPA, Department of Energy, CNMF and Department of the Treasury | government_advisory | public | 1 |
| FBI, CISA, NSA, EPA, Israel National Cyber Directorate, Canadian Centre for Cyber Security and NCSC-UK | government_advisory | public | 1 |
| FBI, CISA, NSA, Polish SKW, CERT Polska and NCSC-UK | government_advisory | public | 1 |
| FBI, NSA and CISA | government_advisory | public | 1 |
| Ginesin | academic_research | public | 1 |
| Google Threat Intelligence Group | vendor_research | public | 1 |
| GuidePoint Security | vendor_research | public | 1 |
| NCSC-UK with fourteen international partner agencies | government_advisory | public | 1 |
| NCSC-UK, ACSC, CCCS, NCSC-NZ, CISA, NSA and FBI | government_advisory | public | 1 |
| NCSC-UK, CISA, FBI and NSA | government_advisory | public | 1 |
| NCSC-UK, CISA, FBI, NSA, CNMF, Australian Cyber Security Centre, Canadian Centre for Cyber Security and NCSC-NZ | government_advisory | public | 1 |
| NCSC-UK, CISA, NSA and FBI | government_advisory | public | 1 |
| NCSC-UK, NSA, CISA, CNMF, FBI, ACSC, Canadian Centre for Cyber Security and GCSB | government_advisory | public | 1 |
| NSA, CISA, FBI, Australian Cyber Security Centre, Canadian Centre for Cyber Security and NCSC-NZ | government_advisory | public | 1 |
| NSA, CISA, FBI, DC3 and fourteen international partner agencies | government_advisory | public | 1 |
| NSA, FBI, CISA, HHS, Republic of Korea National Intelligence Service and Defense Security Agency | government_advisory | public | 1 |
| NSA, FBI, CISA, Japan National Police Agency and Japan NISC | government_advisory | public | 1 |
| StepSecurity | vendor_research | public | 1 |
| Wang, Hou, Liu, Zhao, Cheng, Zou, Zhang and Wang | academic_research | public | 1 |
