# Git Push Guide

Run these commands from the extracted `ThreatLens` project folder.

```bash
git init
git add .
git commit -m "Prepare ThreatLens CTI dashboard MVP"
git branch -M main
git remote add origin YOUR_GITHUB_REPOSITORY_URL
git push -u origin main
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with the HTTPS or SSH URL of the repository you created on GitHub.

Before pushing, confirm that `.env`, `.venv`, `*.db` and local backups are not staged. They are excluded by `.gitignore`. Never commit API keys or live intelligence data.
