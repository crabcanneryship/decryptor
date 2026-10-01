🔐 decryptor
Local Evidence Decryption Tool

decryptor is a standalone utility written in Go, developed to decrypt forensic evidence collected by the collector during Phase 1 of the pipeline. It is designed for straightforward, local decryption before the transition to fully automated cloud processing.

✨ Key Features
Targeted Utility: Specifically built to handle the encryption schemes used by the collector.

Simple Execution: A single Go-based binary for quick, local processing without complex dependencies.

Phase 1 Native: Optimized for the initial manual-to-cloud transition baseline.

## 🚀 Usage

### Command Line Options
| Option | Description | Required |
| :--- | :--- | :--- |
| `-key` | RSA private key file (.pri or .pem) | `YES` |
| `-in` | Single encrypted input file | `YES, if -dir is not specified` |
| `-dir` | Directory of encrypted files (batch mode) | `YES, if -in is not specified ` |
| `-out` | Output directory | `YES` |
| `-ext` | Extension filter for -dir | `NO` |

### Example
```bash
decryptor.exe -key 26q2.pri -in HOSTNAME.26q2 -out DESTDIR
```
