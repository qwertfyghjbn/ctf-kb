# 检索对照实验

| 指标 | Baseline | Improved |
|---|---:|---:|
| n_scored | 20 | 20 |
| recall_at_5 | 0.65 | 1.0 |
| mrr | 0.625 | 1.0 |
| mismatch_rate | 0.2857142857142857 | 0.0 |
| mismatch_count | 2 | 0 |
| empty_ok | 3 | 4 |
| empty_fail | 1 | 0 |
| fts_errors | 24 | 0 |
| P50 ms | 14.63 | 12.75 |
| P95 ms | 96.67 | 17.29 |

| id | query | B hit | I hit | B ids | I ids | B mismatch | I mismatch |
|---|---|---:|---:|---|---|---|---|
| id-42013 | CVE-2021-42013 | 1 | 1 | CVE-2021-42013 | CVE-2021-42013 | False | False |
| id-5638 | CVE-2017-5638 | 1 | 1 | CVE-2017-5638 | CVE-2017-5638 | False | False |
| id-44228 | CVE-2021-44228 | 1 | 1 | CVE-2021-44228 | CVE-2021-44228 | False | False |
| id-6271 | CVE-2014-6271 | 1 | 1 | CVE-2014-6271 | CVE-2014-6271 | False | False |
| id-0160 | CVE-2014-0160 | 1 | 1 | CVE-2014-0160 | CVE-2014-0160 | False | False |
| pv-httpd-2450 | Apache HTTP Server 2.4.50 | 2 | 1 | CVE-2021-41773,CVE-2021-42013 | CVE-2021-42013,CVE-2021-40438,CVE-2024-38475,CVE-2019-0211,CVE-2021-44790 | True | False |
| pv-httpd-2449 | Apache HTTP Server 2.4.49 | 1 | 1 | CVE-2021-41773,CVE-2021-42013 | CVE-2021-41773,CVE-2021-42013,CVE-2021-40438,CVE-2024-38475,CVE-2019-0211 | False | False |
| pv-struts-259 | Apache Struts 2.5.9 | - | 1 | - | CVE-2017-5638,CVE-2018-11776,CVE-2017-9805,CVE-2017-9791,CVE-2020-17530 | False | False |
| pv-log4j-2141 | Apache Log4j2 2.14.1 | - | 1 | - | CVE-2021-44228,CVE-2021-45105,CVE-2021-44832 | False | False |
| pv-drupal-850 | Drupal 8.5.0 | - | 1 | - | CVE-2018-7600,CVE-2019-6340,CVE-2026-9082,CVE-2020-13671,CVE-2019-6339 | False | False |
| pv-scg-310 | Spring Cloud Gateway 3.1.0 | - | 1 | - | CVE-2022-22947 | False | False |
| pv-openssl-101f | OpenSSL 1.0.1f | - | 1 | - | CVE-2014-0160,CVE-2022-2068,CVE-2022-3786,CVE-2022-3602,CVE-2022-1292 | False | False |
| pv-bash-43 | GNU Bash 4.3 | - | 1 | - | CVE-2014-6271,CVE-2014-7186,CVE-2014-7187,CVE-2014-6278,CVE-2014-7169 | False | False |
| na-httpd-2451 | Apache HTTP Server 2.4.51 | - | - | CVE-2021-44790 | CVE-2021-40438,CVE-2024-38475,CVE-2019-0211,CVE-2021-44790,CVE-2017-9798 | False | False |
| na-struts-2512 | Apache Struts 2.5.12 | - | - | - | CVE-2018-11776,CVE-2017-9805,CVE-2017-9791,CVE-2020-17530,CVE-2019-0230 | False | False |
| na-httpd-245 | Apache HTTP Server 2.4.5 | - | - | CVE-2021-41773,CVE-2021-42013,CVE-2024-38475,CVE-2021-44790,CVE-2023-25690 | CVE-2021-40438,CVE-2024-38475,CVE-2019-0211,CVE-2021-44790,CVE-2017-9798 | True | False |
| na-log4j-2171 | Apache Log4j2 2.17.1 | - | - | CVE-2021-44832 | CVE-2021-45105,CVE-2021-44832 | False | False |
| feat-php-deser | PHP deserialization | - | - | CVE-2022-23940,CVE-2024-24725,CVE-2024-2054,CVE-2023-0960,CVE-2025-15672 | CVE-2019-16894,CVE-2026-58025,CVE-2020-28032,CVE-2023-2288,CVE-2022-23940 | False | False |
| feat-cwe22 | CWE-22 | - | - | CVE-2020-5902,CVE-2022-29464,CVE-2019-19781,CVE-2021-22005,CVE-2023-32315 | CVE-2020-5902,CVE-2022-29464,CVE-2019-19781,CVE-2021-22005,CVE-2023-32315 | False | False |
| feat-log4shell | Log4Shell | 1 | 1 | CVE-2021-44228 | CVE-2021-44228 | False | False |
| feat-shellshock | Shellshock | 1 | 1 | CVE-2014-6271 | CVE-2014-6271 | False | False |
| feat-heartbleed | Heartbleed | 1 | 1 | CVE-2014-0160 | CVE-2014-0160 | False | False |
| syn-foobar | foo-bar | - | - | CVE-2022-31159 | - | False | False |
| syn-openssh | OpenSSH 8.4 | - | - | - | CVE-2026-123158,CVE-2025-26466,CVE-2025-26465,CVE-2025-61984,CVE-2026-35414 | False | False |
| syn-nginx-slash | nginx/1.18.0 | - | - | - | CVE-2025-1974,CVE-2025-1098,CVE-2026-42945,CVE-2023-5044,CVE-2021-23017 | False | False |
| none-fake | NonexistentSoft 9.9.9 | - | - | - | - | False | False |
| none-cve | CVE-9999-0001 | - | - | - | - | False | False |
| none-xyzzy | xyzzy-unknown-product | - | - | - | - | False | False |
