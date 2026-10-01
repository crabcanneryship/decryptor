🔐 decryptor
Local Evidence Decryption Tool

decryptor is a standalone utility written in Go, developed to decrypt forensic evidence collected by the collector. It is designed for straightforward, local decryption before the transition to fully automated cloud processing.

✨ Key Features
Targeted Utility: Specifically built to handle the encryption schemes used by the collector.

Simple Execution: A single Go-based binary for quick, local processing without complex dependencies.

📘Note
This is just an adhoc decryption tool for PoC (manually loading data into OpenSearch and BigQuery). Please see @veloxamen for fully automated processing.

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
