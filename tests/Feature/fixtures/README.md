# Test Fixtures for Redactor Scan Command

This directory contains various test fixtures designed to test different aspects of the `redactor:scan` command functionality.

## File Types and Expected Results

### Clean Files (Should show CLEAN status)
- `clean-text-file.txt` - Plain text file with no sensitive information
- `clean-config.json` - JSON configuration file without secrets
- `clean-environment.env` - Environment file with non-sensitive settings
- `subdirectory/clean-config.yml` - YAML configuration without secrets

### Files with Sensitive Content (Should show FINDINGS status)
- `sensitive-api-keys.txt` - Various API keys and tokens
- `personal-info.txt` - Personal information (emails, phone, SSN, credit cards)
- `sensitive-config.json` - JSON with database passwords and API keys
- `environment-secrets.env` - Environment file with passwords and secrets
- `high-entropy-strings.txt` - High-entropy strings that trigger Shannon entropy detection
- `mixed-content.txt` - Mix of normal log entries and sensitive data
- `test-sensitive-file.txt` - Original test file with JSON containing secrets
- `subdirectory/nested-secrets.yml` - YAML file with various secrets and tokens

### Special Test Cases (File Filtering)
- `unreadable-file.txt` - File with no read permissions (should be filtered out during collection)
- `large-file.txt` - File larger than 10MB (should be filtered out during collection)
- `subdirectory/unreadable-file.txt` - Unreadable file in subdirectory (tests subdirectory filtering)
- `subdirectory/large-file.txt` - Large file in subdirectory (tests subdirectory filtering)

## Testing Scenarios

### Single File Scanning
```bash
./vendor/bin/testbench redactor:scan tests/Feature/fixtures/clean-text-file.txt
./vendor/bin/testbench redactor:scan tests/Feature/fixtures/sensitive-api-keys.txt
```

### Multiple File Scanning
```bash
./vendor/bin/testbench redactor:scan tests/Feature/fixtures/clean-text-file.txt tests/Feature/fixtures/sensitive-api-keys.txt
```

### Directory Scanning
```bash
./vendor/bin/testbench redactor:scan tests/Feature/fixtures/
./vendor/bin/testbench redactor:scan tests/Feature/fixtures/subdirectory/
```

### Mixed Scanning (Files + Directories)
```bash
./vendor/bin/testbench redactor:scan tests/Feature/fixtures/clean-text-file.txt tests/Feature/fixtures/subdirectory/
```

### Output Formats
```bash
# Table output (default)
./vendor/bin/testbench redactor:scan tests/Feature/fixtures/clean-text-file.txt

# JSON output
./vendor/bin/testbench redactor:scan tests/Feature/fixtures/clean-text-file.txt --output=json
```

### Options Testing
```bash
# Summary only (no per-file table)
./vendor/bin/testbench redactor:scan tests/Feature/fixtures/ --summary-only

# Bail on findings (exit code 1 if findings detected)
./vendor/bin/testbench redactor:scan tests/Feature/fixtures/sensitive-api-keys.txt --bail

# Custom profile
./vendor/bin/testbench redactor:scan tests/Feature/fixtures/sensitive-api-keys.txt --profile=default
```

## Expected Results Summary

When scanning all fixtures:
- **Clean files**: 4 files (clean-text-file.txt, clean-config.json, clean-environment.env, subdirectory/clean-config.yml)
- **Files with findings**: 8 files (all sensitive content files)
- **Filtered out**: 4 files (large-file.txt, unreadable-file.txt, and their subdirectory versions)

The redactor uses the `file_scan` profile by default, which includes:
- Regex pattern matching for emails, phone numbers, credit cards, API keys, etc.
- Shannon entropy detection for high-entropy strings
- No key-based strategies (since plain text files don't have key-value structure) 