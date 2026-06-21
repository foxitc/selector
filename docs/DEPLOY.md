# Auto-deploy to VPS (the "deploy from chat" setup)

This is the process we use to get **TestPlayer-v3** auto-deploying to the VPS on
every push to `main` — the same mechanism behind Todd-v2, rebuilt fresh (no
Todd-v2 code or data copied in).

> **Where this gets done:** in a Claude Code session scoped to
> `foxitc/TestPlayer-v3`, not in the `selector` session. This file is just the
> written-down reference to carry across.

---

## How it actually works

There is no special "deploy" button in chat. The chain is:

```
Claude pushes a commit  ->  push to main  ->  GitHub Actions workflow runs
                                              ->  SSH/rsync to the VPS
                                              ->  files updated (+ service restart)
```

Because Claude does the commit/push from chat, it *looks* like "deploy from
chat" — but the real engine is a GitHub Actions workflow living in the repo plus
a set of VPS secrets.

Two ingredients:
1. **`.github/workflows/deploy.yml`** — committed into the repo.
2. **VPS secrets** — stored in the repo's GitHub Actions settings.

---

## One-time setup

### 1. Kick it off in the TestPlayer-v3 session

In the TestPlayer-v3 composer, send:

> Set up a GitHub Actions pipeline that auto-deploys this repo to my VPS on
> every push to main. Ask me for the VPS details you need.

### 2. Add the VPS secrets

In **TestPlayer-v3 → Settings → Secrets and variables → Actions →
New repository secret**, add:

| Secret name   | What it is                          | Example                  |
| ------------- | ----------------------------------- | ------------------------ |
| `VPS_HOST`    | VPS IP or hostname                  | `203.0.113.10`           |
| `VPS_USER`    | SSH user                            | `deploy`                 |
| `VPS_SSH_KEY` | Private SSH key that can log in     | contents of the key file |
| `DEPLOY_PATH` | Folder on the VPS to deploy into    | `/var/www/testplayer`    |

These are the same *kind* of secrets already set for Todd-v2 / OCHE — reuse the
same VPS host/user/key, just point `DEPLOY_PATH` at this app's own folder.

### 3. The workflow file

Claude will create this in the v3 session. For a **static / PWA (HTML)** app it
looks like this (rsync the files into the web root — no service to restart):

```yaml
name: Deploy to VPS

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up SSH key
        run: |
          mkdir -p ~/.ssh
          echo "${{ secrets.VPS_SSH_KEY }}" > ~/.ssh/id_deploy
          chmod 600 ~/.ssh/id_deploy
          ssh-keyscan -H "${{ secrets.VPS_HOST }}" >> ~/.ssh/known_hosts

      - name: Rsync to VPS
        run: |
          rsync -avz --delete \
            -e "ssh -i ~/.ssh/id_deploy" \
            ./ "${{ secrets.VPS_USER }}@${{ secrets.VPS_HOST }}:${{ secrets.DEPLOY_PATH }}/" \
            --exclude '.git' --exclude '.github'
```

If TestPlayer-v3 turns out to have a **Node backend**, the workflow gains a build
step and a `pm2 restart` (or `systemctl restart`) at the end. Claude detects
which once it's in the repo — you don't need to decide this up front.

---

## After setup

- Every change Claude pushes to `main` deploys automatically.
- Watch a deploy: **TestPlayer-v3 → Actions** tab — green tick = live.
- If a deploy fails, the Actions log shows why (usually a wrong secret or the
  VPS path/permissions).

---

## Notes / gotchas

- The VPS must already have the `DEPLOY_PATH` folder and the deploy user must own
  it (or have write permission).
- The SSH **public** key half must be in the VPS user's
  `~/.ssh/authorized_keys`.
- `--delete` makes the VPS folder mirror the repo exactly — anything on the
  server not in the repo gets removed. Point `DEPLOY_PATH` at this app's own
  folder so it can't wipe anything else.
