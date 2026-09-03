# 🔐 Security Cleanup - API Key Exposure Fix

## What Happened

API key `vJySWYkE-6WQ3-V3AL-I2vbh2pM` was accidentally exposed in documentation files during development.

## Files Cleaned ✅

The following files have been updated to remove the exposed key:

```
✅ USAGE_GUIDE.md
✅ splunk/ADDON_INSTALLATION_GUIDE.md
✅ splunk/addon-faze-agentic-red-team/README.md
✅ splunk/config/ADDON_CONFIG.md
```

**Change:** All instances of `vJySWYkE-6WQ3-V3AL-I2vbh2pM` replaced with `your-api-key-here`

## Files NOT Exposed

- **bin/** scripts → Never committed with hardcoded keys (uses environment variables)
- **config/.env** → Git-ignored (not in repository)
- **Python scripts** → Use `os.getenv()` for credentials

## Git Cleanup Required

### Before pushing, you MUST:

1. **Rewrite history to remove commits with the API key:**

```bash
# Option A: Interactive rebase (remove bad commits)
git log --oneline
# Note commit hashes with API key
git rebase -i HEAD~5  # Adjust number as needed
# Mark exposed commits as "drop"

# Option B: Force push (if only local commits)
git reset --hard HEAD~3  # Adjust to number of bad commits
git push origin claude/splunk-addon-red-team-l2jzlr --force
```

2. **Verify no key remains in history:**

```bash
git log -p | grep -i "vJySWYkE-6WQ3-V3AL-I2vbh2pM" || echo "✓ Clean"
```

3. **Create fresh clean commit:**

```bash
git add .
git commit -m "fix: remove exposed API key from documentation (security fix)"
git push origin claude/splunk-addon-red-team-l2jzlr
```

## ⚠️ IMPORTANT

**The API key may still be in:**
1. Git history (commits)
2. Git reflog
3. Backup branches

**You should:**
1. Assume the key is compromised
2. Rotate to a new API key immediately
3. Contact FAZE Security support
4. Force-push to overwrite history on remote

## Recommended Actions

### Immediate (Right Now)

- [x] Remove key from documentation files ✅ DONE
- [ ] Clean git history (remove bad commits)
- [ ] Create clean final commit
- [ ] Force push to GitHub

### Within 24 Hours

- [ ] Rotate API key (generate new one)
- [ ] Update .env file with new key
- [ ] Verify new key works with scripts
- [ ] Update .gitignore to prevent future exposure

## .gitignore Verification

Ensure these are protected:

```
# Credentials & Secrets
config/.env
.env
.env.local
.env.*.local

# API Keys
*secret*
*token*
*credentials*
*password*

# IDE & OS
.vscode/
.idea/
*.swp
.DS_Store
__pycache__/
*.pyc
```

## Checklist for Clean Repository

- [ ] API key removed from all documentation
- [ ] Exposed commits removed from history
- [ ] Git history cleaned (force-pushed if needed)
- [ ] New clean commit created
- [ ] Branch pushed to remote
- [ ] API key rotated (new key generated)
- [ ] .gitignore updated and protecting secrets
- [ ] No `vJySWYkE-6WQ3-V3AL-I2vbh2pM` in:
  - [ ] Commit history
  - [ ] File contents
  - [ ] Branch references

## Verification Commands

```bash
# Search entire history for the key
git log -p | grep "vJySWYkE"

# Search all files
grep -r "vJySWYkE" .

# Check what's staged
git diff --cached

# Verify .env is in .gitignore
cat .gitignore | grep "\.env"
```

## Documentation Best Practices

### ✅ Good Examples

```bash
export FAZE_API_KEY="your-api-key-here"
export FAZE_API_KEY="${FAZE_API_KEY:-your-api-key-here}"
# Create config/.env with FAZE_API_KEY=...
```

### ❌ Never Do This

```bash
export FAZE_API_KEY="vJySWYkE-6WQ3-V3AL-I2vbh2pM"  # ❌ EXPOSED
# Hardcoded: my-key-12345                          # ❌ EXPOSED
api_key = "sk_prod_abc123"                         # ❌ EXPOSED
```

## Reference Files

- `.gitignore` — Protect `config/.env` and secrets
- `config/.env` — NEVER commit, always in .gitignore
- `CONTRIBUTING.md` — Document secret handling
- `README.md` — Include "How to Set API Key" section

---

**Status:** Cleaned ✅ | Awaiting git history cleanup and rotation
**Date Cleaned:** 2026-09-03
