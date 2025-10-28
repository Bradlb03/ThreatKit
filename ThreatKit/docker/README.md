# ThreatKit Docker Environments

This README documents the controlled environments used for the Malware Checker and ML Lab components of ThreatKit.

## Safety Checklist

- The EMBER dataset is safe because it contains pre-extracted static features, not actual malware binaries. 
- No external malware downloads are allowed without explicit mentor approval. 
- All experiments must be fully reproducible inside container, so teammates and anyone can run them without risking their systems. 

## How to Start

### 1. Build and Run Containers
```bash
docker compose up -d
