# Deploying Messager

How to run the app on a server of your own, keep it updated, and back it up.

The stack is three containers run by Docker Compose (`docker-compose.prod.yml`):

```
internet ──80/443──> Caddy (HTTPS, automatic certificates)
                       └──> app (web app + API + WebSocket)
                              └──> Postgres
```

Only Caddy is reachable from outside. The app and the database sit on
internal Docker networks, and the database has no route to the internet at
all.

**Before inviting anyone:** the M2 design requires forward secrecy and
identity backup to be finished first. Until then a deployment is for the
original two users' private testing only.

## 1. What you need

- A small Linux server (1 GB RAM is enough). These notes assume Ubuntu 24.04.
- A domain name with an `A` record (and `AAAA` if the server has IPv6)
  pointing at the server. Caddy cannot obtain a certificate until this resolves.
- An SSH key on your own computer.

## 2. Secure the server (once)

Log in as root the first time, then:

```bash
# A normal user for everything from here on.
adduser deploy
usermod -aG sudo deploy
rsync --archive --chown=deploy:deploy ~/.ssh /home/deploy
```

Log out and back in as `deploy`, and check `sudo -v` works **before** the
next step, or you can lock yourself out.

```bash
# SSH: keys only, no root.
sudo tee /etc/ssh/sshd_config.d/99-hardening.conf >/dev/null <<'CONF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
CONF
sudo systemctl restart ssh

# Firewall: SSH, HTTP and HTTPS only.
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Security updates install themselves.
sudo apt update && sudo apt install -y unattended-upgrades age
sudo dpkg-reconfigure -plow unattended-upgrades
```

Install Docker from Docker's own repository (https://docs.docker.com/engine/install/ubuntu/),
then let the `deploy` user run it:

```bash
sudo usermod -aG docker deploy    # log out and in again afterwards
```

Docker publishes container ports itself and does not consult `ufw`. That is
fine here because the Compose file publishes only Caddy's 80 and 443; do not
add `ports:` to the other services.

## 3. First deploy

```bash
git clone https://github.com/EllaFawn/messenger.git
cd messenger
git checkout <tag>                 # a released tag, not a moving branch

cp deploy/env.prod.example .env.prod
chmod 600 .env.prod
nano .env.prod                     # set DOMAIN, and POSTGRES_PASSWORD from: openssl rand -hex 24

docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

The app container applies database migrations each time it starts. Check it:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod ps
curl https://<your domain>/api/health        # {"status":"ok"}
```

The first HTTPS request can take a few seconds while Caddy obtains the certificate.

## 4. Invites and accounts

The operator commands run inside the app container:

```bash
alias mgr='docker compose -f docker-compose.prod.yml --env-file .env.prod exec app node packages/server/dist/cli/admin-cli.js'

mgr invite create --note "for Sam"
mgr invite list
mgr invite revoke <invite id>
mgr user list
mgr user remove <userID> --yes
```

## 5. Updating

```bash
git fetch --tags
git checkout <new tag>
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
curl https://<your domain>/api/health
```

Take a backup first (section 6). To go back, check out the previous tag and
run the same `up` command. A release that changed the database cannot always
be rolled back this way; its notes will say so, and then the answer is to
restore the backup.

## 6. Backups

The database holds public keys, encrypted messages awaiting delivery, invite
records and metadata. It never holds message text or private keys. It still
needs backing up: losing it means everyone has to register again.

Backups are encrypted to a public key, so the server can create them but
cannot read them.

**Once, on your own computer (not the server):**

```bash
age-keygen -o messager-backup-key.txt     # prints "Public key: age1..."
```

Keep `messager-backup-key.txt` somewhere safe and off the server. Without it
the backups are unreadable.

**On the server:**

```bash
BACKUP_RECIPIENT=age1... ./deploy/backup.sh
```

This writes `backups/messager-<time>.dump.age` and deletes backups older
than 14 days. To run it nightly, `crontab -e`:

```
15 3 * * * cd /home/deploy/messenger && BACKUP_RECIPIENT=age1... ./deploy/backup.sh >> backups/backup.log 2>&1
```

Copy the files off the server regularly (for example with `rsync` from your
own computer). A backup that lives only on the server it protects is lost
with it.

**Restoring** (on the server, with the key file copied over temporarily):

```bash
C="docker compose -f docker-compose.prod.yml --env-file .env.prod"
$C stop app
age -d -i messager-backup-key.txt backups/messager-<time>.dump.age \
  | $C exec -T postgres pg_restore -U messager -d messager --clean --if-exists
$C start app
shred -u messager-backup-key.txt
```

Rehearse this once before relying on it.

## 7. Trying the production stack on your own computer

With `DOMAIN=localhost` Caddy issues a certificate from its own local
authority, so the whole stack runs on a laptop:

```bash
printf 'DOMAIN=localhost\nPOSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 24)" > .env.prod
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

Open https://localhost and accept the browser's certificate warning (the
certificate is local, not publicly trusted). If ports 80 or 443 are in use,
add `HTTP_PORT=8080` and `HTTPS_PORT=8443` to `.env.prod` and open
https://localhost:8443.

To remove it again, including its data:

```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod down --volumes
```

## 8. What this does and does not protect

- Traffic is encrypted in transit by HTTPS, and messages are encrypted end
  to end on top of that.
- The app container runs as an unprivileged user, cannot gain privileges,
  and cannot write to its own filesystem.
- No access log is kept.
- **Whoever controls this server controls the web app it serves**, and could
  serve a version that leaks keys. Everything here is only as trustworthy as
  the server and its operator.

## 9. If this outgrows one server

Nothing in the app knows it runs in a container, so moving to a managed
database or another host is a change of settings. Two things are tied to a
single app process and would need a shared store first: the rate limits and
the list of open push connections.
