#!/usr/bin/env bash
set -euo pipefail
umask 022

[[ $# == 3 && $EUID == 0 ]] || {
    echo 'Usage: install-recite-update.sh RECEIVER SSH_PUBLIC_KEY MANIFEST_PUBLIC_KEY' >&2
    exit 2
}
receiver=$1
ssh_key=$2
manifest_key=$3
account=recite-update
home=/var/lib/recite-update
service=/usr/local/lib/recite-update
keys=/etc/apphub/recite-update/keys
apps=/opt/apphub/apps
config=$apps/Caddyfile
site=$apps/site/updates
root=$site/recite-publisher
lane=dictionary/beta/android
kid=recite-beta-android-1
container=apphub-web-caddy-1

[[ -f $receiver && -f $ssh_key && -f $manifest_key && -f $config && -d $site ]]
read -r kind public_key _ < "$ssh_key"
[[ $kind == ssh-ed25519 && $public_key =~ ^[A-Za-z0-9+/=]+$ ]]
ssh-keygen -lf "$ssh_key" >/dev/null
details=$(openssl rsa -pubin -in "$manifest_key" -text -noout)
case "$details" in
    'Public-Key: (3072 bit)'* | 'RSA Public-Key: (3072 bit)'*) ;;
    *) echo 'Expected a 3072-bit RSA public key' >&2; exit 1 ;;
esac
python3 -I "$receiver" --help >/dev/null

exec 9>"$apps/site-update.lock"
flock -x 9
candidate=$(mktemp "$site/.recite-caddy.XXXXXX")
trap 'rm -f -- "$candidate"' EXIT
python3 - "$config" "$candidate" <<'PY'
from pathlib import Path
import re
import sys

source, candidate = map(Path, sys.argv[1:])
config = source.read_text()
header = "update.0979019203.top {"
if config.count(header) != 1:
    raise SystemExit("Update virtual host is missing or ambiguous")
start = config.index(header)
end = config.index("\n}", start)
site = config[start:end]
anchor = re.search(r"(?m)^[ \t]+@manifest path /calculus/stable/android/latest\.json$", site)
if anchor is None:
    raise SystemExit("Existing calculus update route is missing")

routes = r"""    @recite_manifest path /dictionary/beta/android/latest.json
    handle @recite_manifest {
        root * /srv/updates/recite-publisher
        header Cache-Control "no-store"
        file_server
    }

    @recite_package path_regexp recite_apk ^/dictionary/beta/android/releases/[1-9][0-9]*/package\.apk$
    handle @recite_package {
        root * /srv/updates/recite-publisher
        header Cache-Control "public, max-age=31536000, immutable"
        file_server
    }

"""
if "@recite_manifest" in site or "@recite_package" in site:
    if routes not in site:
        raise SystemExit("A different Recite route is already configured")
else:
    position = start + anchor.start()
    config = config[:position] + routes + config[position:]
candidate.write_text(config)
PY
docker exec "$container" caddy validate --config "/srv/updates/${candidate##*/}" --adapter caddyfile

if ! id "$account" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir "$home" --shell /bin/sh "$account"
fi
[[ $(getent passwd "$account" | cut -d: -f6,7) == "$home:/bin/sh" ]]
install -d -o root -g "$account" -m 0750 "$home" "$home/.ssh"
install -d -o root -g root -m 0755 "$service" "$keys/$lane" "$root" "$root/dictionary" "$root/dictionary/beta"
install -d -o "$account" -g "$account" -m 0755 "$root/$lane" "$root/$lane/releases"
install -d -o root -g "$account" -m 0750 "$root/.state"
install -d -o "$account" -g "$account" -m 0700 "$root/.state/inbox" "$root/.state/locks"
line="restrict,command=\"/usr/bin/timeout -k 10s 15m /usr/bin/python3 -I $service/receiver.py receive dictionary beta android $kid\" $kind $public_key $lane"
authorized=$home/.ssh/authorized_keys
if [[ -e $authorized ]] && ! cmp -s "$authorized" <(printf '%s\n' "$line"); then
    echo 'A different Recite publisher key already exists' >&2
    exit 1
fi
if [[ -e $keys/$lane/$kid.pem ]] && ! cmp -s "$manifest_key" "$keys/$lane/$kid.pem"; then
    echo 'A different Recite manifest key already exists' >&2
    exit 1
fi
install -o root -g root -m 0644 "$receiver" "$service/receiver.py"
install -o root -g root -m 0644 "$manifest_key" "$keys/$lane/$kid.pem"
install -o root -g "$account" -m 0640 <(printf '%s\n' "$line") "$authorized"

if ! cmp -s "$candidate" "$config"; then
    backup=$(mktemp "$apps/Caddyfile.before-recite.XXXXXX")
    cp -p "$config" "$backup"
    # Keep the inode mounted read-only into the Caddy container.
    if ! cat "$candidate" > "$config" ||
        ! docker exec "$container" caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile; then
        cat "$backup" > "$config"
        docker exec "$container" caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
        exit 1
    fi
fi
printf 'Ready: %s\n' "$lane"
