# Python SAST Auto-Remediation with Cursor CLI

This project demonstrates automated security vulnerability detection and remediation using:
- **Snyk Code** for Static Application Security Testing (SAST)
- **Cursor CLI** for AI-powered automatic code remediation
- **GitHub Actions** for CI/CD pipeline orchestration

## Overview

The workflow automatically:
1. Scans Python code for security vulnerabilities using Snyk Code
2. Uses Cursor AI to automatically fix detected vulnerabilities
3. Commits the remediated code back to the branch

## Project Structure

```
github-actions-remediation/
├── src/
│   └── vulnerable_app.py      # Flask app with intentional vulnerabilities
├── tests/
│   └── test_app.py            # Basic tests
├── .github/
│   └── workflows/
│       └── auto-remediate.yml # GitHub Actions workflow
├── requirements.txt           # Python dependencies
├── .gitignore
└── README.md
```

## Intentional Vulnerabilities

The `src/vulnerable_app.py` contains these common security vulnerabilities for demonstration:

| Vulnerability | Description | CWE |
|--------------|-------------|-----|
| SQL Injection | User input concatenated into SQL queries | CWE-89 |
| Command Injection | User input passed to `os.system()` and `subprocess` with `shell=True` | CWE-78 |
| Path Traversal | Unsanitized file paths allowing `../` escapes | CWE-22 |
| Hardcoded Secrets | API keys and passwords in source code | CWE-798 |
| Insecure Deserialization | `pickle.loads()` on untrusted data | CWE-502 |
| Code Injection | `eval()` on user input | CWE-94 |

## Setup

### Prerequisites

- GitHub repository with Actions enabled
- [Snyk account](https://snyk.io/) with API token
- [Cursor API key](https://cursor.com/) for CLI access

### Configure Repository Secrets

Add these secrets to your GitHub repository (Settings → Secrets and variables → Actions):

| Secret | Description | Required |
|--------|-------------|----------|
| `SNYK_TOKEN` | Snyk API token for code scanning | Yes |
| `CURSOR_API_KEY` | Cursor API key for AI remediation | Yes |

#### Getting Your Snyk Token

1. Log in to [Snyk](https://app.snyk.io/)
2. Go to Account Settings → API Token
3. Copy the token and add it as `SNYK_TOKEN` secret

#### Getting Your Cursor API Key

1. Open Cursor IDE or visit [Cursor Dashboard](https://cursor.com/)
2. Go to Settings → Integrations
3. Generate an API key and add it as `CURSOR_API_KEY` secret

## Usage

### Automatic Remediation (Default)

The workflow runs automatically on:
- Push to `main` or `feature/**` branches
- Pull requests to `main`

When vulnerabilities are detected:
1. Snyk Code scans the codebase
2. Results are passed to Cursor AI
3. Cursor applies security fixes
4. Changes are committed and pushed

### Manual Trigger

You can also trigger the workflow manually:

1. Go to Actions → Auto-Remediate Security Vulnerabilities
2. Click "Run workflow"
3. Select the branch and click "Run workflow"

## Local Development

### Running Locally

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the app (for testing only!)
python src/vulnerable_app.py
```

### Running Snyk Locally

```bash
# Install Snyk CLI
npm install -g snyk

# Authenticate
snyk auth

# Run SAST scan
snyk code test
```

## How the Remediation Works

### 1. Snyk Code Scan

Snyk Code performs static analysis to detect:
- Injection vulnerabilities (SQL, Command, Code)
- Path traversal issues
- Hardcoded credentials
- Insecure data handling

### 2. Cursor AI Remediation

The Cursor CLI receives the Snyk results and applies fixes:

```yaml
agent -p --force "
  Read snyk-results.json and fix each vulnerability:
  - SQL Injection → Parameterized queries
  - Command Injection → subprocess with list args
  - Path Traversal → Path validation
  - Hardcoded Secrets → Environment variables
"
```

### 3. Git Commit

Fixes are committed using conventional commit format:

```
fix(security): auto-remediate SAST vulnerabilities

Automated security fixes applied by Cursor CLI based on Snyk Code scan.

Co-authored-by: Cursor AI <noreply@cursor.com>
Co-authored-by: Snyk <noreply@snyk.io>
```

## Git Best Practices

This project follows these git conventions:
- **Conventional Commits**: `fix(security):` prefix for security fixes
- **Co-authored-by**: Attribution for AI-generated changes
- **Atomic Commits**: One commit per remediation run
- **No Force Pushes**: Clean history preservation
- **Protected Branches**: Compatible with branch protection rules

## Alternative: PR-Based Workflow

For more control, you can modify the workflow to create a PR instead of direct commits:

```yaml
- name: Create Fix PR
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    BRANCH="security/auto-fix-$(date +%Y%m%d-%H%M%S)"
    git checkout -b "$BRANCH"
    git add -A
    git commit -m "fix(security): auto-remediate vulnerabilities"
    git push -u origin "$BRANCH"
    gh pr create \
      --title "Security: Auto-remediated vulnerabilities" \
      --body "Automated security fixes from Snyk + Cursor"
```

## Security Considerations

- **Never commit secrets**: Use environment variables and GitHub Secrets
- **Review AI changes**: Consider using PR-based workflow for manual review
- **Test after remediation**: Ensure fixes don't break functionality
- **Monitor scan results**: Track vulnerability trends over time

## Troubleshooting

### Snyk scan not finding vulnerabilities

- Ensure `SNYK_TOKEN` is correctly configured
- Check that Snyk Code is enabled for your organization
- Verify the file extensions are supported by Snyk

### Cursor CLI not making changes

- Verify `CURSOR_API_KEY` is valid
- Check the workflow logs for error messages
- Ensure the prompt provides clear remediation instructions

### Git push failing

- Check repository permissions for `GITHUB_TOKEN`
- Verify branch protection rules allow bot commits
- Ensure `contents: write` permission is set

## License

MIT License - This is a demonstration project for educational purposes.

## Warning

**DO NOT deploy the vulnerable code to production!** This project is intended solely for demonstrating automated security remediation workflows.
