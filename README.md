# python-crypto-benchmark

A basic benchmark of multiple Python crypto libs.

```
pyflocker cryptography aesgcm
encrypt 1113 MB/s

cryptography.hazmat aesgcm
encrypt 1054 MB/s

cryptography.hazmat chacha20poly1305
encrypt 871 MB/s
```

# In mem
| MB    | Seconds |
| -------- | ------- |
|0.0625 | 0.00013|
|0.125 | 0.00013|
|0.25 | 0.00016|
|0.5 | 0.00022|
|1.0 | 0.00033|
|2.0 | 0.00057|
|4.0 | 0.00102|
|8.0 | 0.00194|
|16.0 | 0.00372|
|32.0 | 0.00785|
|64.0 | 0.01530|
|128.0 | 0.02921|
|256.0 | 0.05991|
|512.0 | 0.11713|
|1024.0 | 0.23630|
|2048.0 | 0.51583|
|4096.0 | 1.04500|
|8192.0 | 2.01338|

# File
| MB    | Seconds |
| -------- | ------- |
|0.0625 | 0.84755|
|0.125 | 0.67452|
|0.25 | 0.63874|
|0.5 | 0.64462|
|1.0 | 0.59746|
|2.0 | 0.57674|
|4.0 | 0.58840|
|8.0 | 0.63488|
|16.0 | 0.60501|
|32.0 | 0.73886|
|64.0 | 0.72090|
|128.0 | 0.70522|
|256.0 | 0.75242|
|512.0 | 0.75465|
|1024.0 | 0.77794|

# Contribute

Feel free to fork it, change and use it in any way that you want.
If you build something interesting and feel like sharing pull requests are always appreciated.

## How to contribute

Please see [CONTRIBUTING.md](CONTRIBUTING.md).
