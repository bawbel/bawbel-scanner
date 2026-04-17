# Docker — Bawbel Scanner

Run the scanner without any local Python installation.

---

## Quick Start

```bash
# Build
docker build -t bawbel/scanner:0.1.0 .

# Scan a local file
docker run --rm \
  -v $(pwd)/my-skill.md:/scan/skill.md:ro \
  bawbel/scanner:0.1.0 scan /scan/skill.md

# Scan a local directory
docker run --rm \
  -v $(pwd)/skills:/scan:ro \
  bawbel/scanner:0.1.0 scan /scan --recursive

# JSON output
docker run --rm \
  -v $(pwd)/skills:/scan:ro \
  bawbel/scanner:0.1.0 scan /scan --recursive --format json
```

---

## Docker Compose

```bash
# Create scan directory and add files
mkdir scan
cp my-skill.md scan/

# Run (text output)
docker-compose up

# Run (JSON output)
docker-compose --profile json up scanner-json
```

---

## Security Configuration

The Docker image follows least-privilege:

```dockerfile
# Non-root user
USER bawbel

# Read-only volume mount
volumes:
  - ./scan:/scan:ro

# No privilege escalation
security_opt:
  - no-new-privileges:true
```

**Never override these for scan operations.**

---

## Environment Variables in Docker

```bash
docker run --rm \
  -v $(pwd)/skills:/scan:ro \
  -e BAWBEL_LOG_LEVEL=INFO \
  -e BAWBEL_MAX_FILE_SIZE_MB=50 \
  bawbel/scanner:0.1.0 scan /scan --recursive
```

For LLM analysis (Stage 2):

```bash
docker run --rm \
  -v $(pwd)/skills:/scan:ro \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  bawbel/scanner:0.1.0 scan /scan --recursive
```

---

## Image Tags

| Tag | Description |
|---|---|
| `bawbel/scanner:0.1.0` | Specific version — recommended for production |
| `bawbel/scanner:latest` | Latest release |
| `bawbel/scanner:dev` | Local development build |

---

## Building Locally

```bash
# Standard build
docker build -t bawbel/scanner:dev .

# With build cache
docker build --cache-from bawbel/scanner:latest -t bawbel/scanner:dev .

# Check image size
docker images bawbel/scanner
```
