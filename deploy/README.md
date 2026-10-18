# recon-rs — deployment (systemd `--user` timers, one per target)

Runs `recon-cli` scans unattended, on independent staggered schedules, one target at a
time, as your own non-root user account — no root, no system-wide service, no cron.
Each target is one instance of a systemd template unit
(`recon-rs@<name>.service`/`recon-rs@<name>.timer`, e.g. `recon-rs@vfc.timer`), so
nothing runs in one continuous loop and nothing runs simultaneously by default — see
"How the schedule is kept non-overlapping" below.

Bootstrapped out of the box for VF Corporation's VDP (HackerOne): `vfc` (vfc.com),
`vans` (vans.com), `thenorthface` (thenorthface.com), `timberland` (timberland.com),
`vfc-int` (vfc-int.com) — see "Add a target" to extend this to another program.

## ⚠️ Before you enable this against any target

Each `targets/<name>.env` is a static file. The bug bounty program it points at is
not. **Before enabling a target's timer, and periodically while it keeps running
unattended, re-read that program's current scope and rules yourself** (its
HackerOne/Bugcrowd page, or wherever it publishes them) — programs add/remove domains
from scope and change their rate-limit rules over time, and this file will happily keep
running with whatever was true the day you last edited it. `recon-cli` will refuse a
scan whose `--target` isn't covered by `--program`'s `[scope]`, but it has no way to
know if that `[scope]` itself has gone stale.

## Install

```sh
./deploy/install.sh
```

Never run this with `sudo`. It:

1. Builds `recon-cli` with `cargo build --release`.
2. Installs the binary to `~/.local/bin/recon-cli`.
3. Copies `config/` to `~/.config/recon-rs/config/` (a stable location, decoupled from
   wherever this git checkout happens to live) — this includes
   `config/programs/vfc-vdp.toml`, shared by all 5 VF sub-targets (see "One program
   config, five targets" below).
4. Installs the `recon-rs@.service`/`recon-rs@.timer` **template** units to
   `~/.config/systemd/user/`.
5. Bootstraps `~/.config/recon-rs/targets/{vfc,vans,thenorthface,timberland,vfc-int}.env`
   from `deploy/recon-rs.env.example`, and a per-target schedule drop-in at
   `~/.config/systemd/user/recon-rs@<name>.timer.d/schedule.conf` — **only for files
   that don't already exist**; a re-run of `install.sh` (e.g. after `git pull`) never
   clobbers your edited settings.
6. If it finds the old (pre-multi-target) `recon-rs.service`/`recon-rs.timer` still
   installed, disables and removes them — superseded by `recon-rs@vfc.*`. Your scan
   history in the database is untouched either way.
7. Reloads systemd, then enables + starts `recon-rs@<name>.timer` for **every**
   `*.env` file actually present in `targets/` — not hardcoded to the 5 bootstrapped
   above, so a target you add by hand (see "Add a target") gets enabled too on the
   next `install.sh` run.

Each target's timer is enabled at the end of `install.sh`, but a scan will only
actually succeed once you've edited its environment file:

```sh
$EDITOR ~/.config/recon-rs/targets/vfc.env
```

`TARGET` and `PROGRAM_CONFIG` are already filled in correctly for the 5 bootstrapped
VF targets. Set `SEED_FILE` (create the seed file itself too — one already-known FQDN
per line) and `DATABASE_URL` (same value in every `targets/*.env` — see "One database,
five targets"). Until you do, the first scheduled run for that target will just fail
cleanly and log why — it will not retry aggressively or spam the target (see "Failure
behavior").

## One program config, five targets

`config/programs/vfc-vdp.toml`'s `[scope]` already lists all five VF sub-brand
domains — it's the whole VF Corporation VDP program's rules, not one domain's. Every
`targets/*.env`'s `PROGRAM_CONFIG` points at that **same** file; `recon-cli` checks
`--target` against the full `[scope].domains` list regardless of which one you pass, so
`--target vans.com --program vfc-vdp.toml` is authorized exactly like `--target vfc.com`
is — no per-domain duplicate of the program file needed. Only duplicate it if a
different program with genuinely different rate limits/headers is involved (see "Add a
target" for a program VF Corp doesn't own).

## One database, five targets

All `targets/*.env` should share the same `DATABASE_URL`. Scan history for every
target lives in the same `scans`/`scan_results` tables, one row set per scan run,
differentiated by `target_domain` — not one database per target.

## How the schedule is kept non-overlapping

The `recon-rs@.timer` template has **no `OnCalendar=` of its own on purpose** — every
instance's real schedule lives in its own drop-in,
`~/.config/systemd/user/recon-rs@<name>.timer.d/schedule.conf`. `install.sh` stages
the 5 bootstrapped VF targets 4 hours apart (`vfc` 00:00, `vans` 04:00, `thenorthface`
08:00, `timberland` 12:00, `vfc-int` 16:00), each with `RandomizedDelaySec=30min` on
top so it doesn't fire at exactly the same second every day. If you ever enable a
target's timer *without* a matching drop-in, it loads fine but simply never fires —
this fails safe (nothing runs) rather than unsafe (everything inheriting some default
and firing in lockstep).

## Verify the timers are active

```sh
systemctl --user list-timers 'recon-rs@*'
```

Shows every enabled target's next scheduled run and, once one has happened, its last
one — confirm the times are actually spread out the way you expect. For one target:

```sh
systemctl --user status recon-rs@vfc.timer
systemctl --user status recon-rs@vfc.service
```

To trigger one target's run right now instead of waiting for its schedule (useful
right after editing its `.env`):

```sh
systemctl --user start recon-rs@vfc.service
```

## Logs

Per target:

```sh
journalctl --user -t recon-rs-vfc -f
```

Every target's `SyslogIdentifier` is `recon-rs-<name>`, so this filters cleanly without
needing the full instantiated unit-name syntax. All targets at once:

```sh
journalctl --user -u 'recon-rs@*.service' -f
```

Drop `-f` to see history instead of following live. Each run is one `recon-cli`
invocation's `tracing` output (stage-by-stage progress) plus its final Markdown report
path. Reports land in `~/.config/recon-rs/reports/` (shared directory, filenames are
already `{target}_{timestamp}.md` / `{target}_latest.md` per target).

## Failure behavior

Every `recon-rs@<name>.service` has `Restart=no` and no retry logic of any kind. If a
run fails (unreachable `DATABASE_URL`, a `--target` that fails the `--program` scope
check, a malformed config path), it fails once, logs the reason to journald, and simply
waits for that target's own `recon-rs@<name>.timer`'s next scheduled occurrence — it
never retries immediately, and a failure on one target never affects any other
target's independent schedule. This is deliberate: a scan failing for a real,
persistent reason (bad config, revoked scope) must never turn into a tight loop
hammering the target with repeated failed attempts.

## Change a target's domain, program, or seed file

Edit `~/.config/recon-rs/targets/<name>.env` (not anything under `deploy/` — that's the
template, not the live config) and either wait for the next run or trigger one
immediately with `systemctl --user start recon-rs@<name>.service`. No rebuild, no
restart of the timer needed — the service reads its environment file fresh on every
run.

## Change a target's frequency

Edit `~/.config/systemd/user/recon-rs@<name>.timer.d/schedule.conf`, then:

```sh
systemctl --user daemon-reload
systemctl --user restart recon-rs@<name>.timer
```

See `systemd.time(7)` for `OnCalendar` syntax (e.g. `OnCalendar=Mon *-*-* 03:00:00` for
weekly). When picking a new time, check `systemctl --user list-timers 'recon-rs@*'`
first so you don't land on another target's slot.

## Add a target

For a 6th VF sub-brand domain later added to the program's scope: add it to
`config/programs/vfc-vdp.toml`'s `[scope].domains`, then follow the steps below with
`PROGRAM_CONFIG` still pointing at that same file.

For an entirely different program (not VF Corp): create its own
`config/programs/<program>.toml` first (see the existing `vfc-vdp.toml` for the
format), then:

```sh
name=newtarget   # your choice — this becomes the recon-rs@<name> instance name

# 1. Environment file
sed \
    -e "s#__TARGET__#some-domain.example#g" \
    -e "s#__PROGRAM_CONFIG__#$HOME/.config/recon-rs/config/programs/<program>.toml#g" \
    -e "s#__NAME__#${name}#g" \
    deploy/recon-rs.env.example > "$HOME/.config/recon-rs/targets/${name}.env"
chmod 600 "$HOME/.config/recon-rs/targets/${name}.env"
$EDITOR "$HOME/.config/recon-rs/targets/${name}.env"   # SEED_FILE, DATABASE_URL

# 2. Schedule — pick a time that doesn't collide with an existing target
#    (check: systemctl --user list-timers 'recon-rs@*')
mkdir -p "$HOME/.config/systemd/user/recon-rs@${name}.timer.d"
cat > "$HOME/.config/systemd/user/recon-rs@${name}.timer.d/schedule.conf" << 'EOF'
[Timer]
OnCalendar=*-*-* 20:00:00
EOF

# 3. Enable
systemctl --user daemon-reload
systemctl --user enable --now "recon-rs@${name}.timer"
```

No code changes, no edits to `deploy/install.sh` required — re-running `install.sh`
later won't touch or duplicate anything you set up by hand this way (it only bootstraps
the 5 VF names, and only if their `.env` doesn't already exist).

## Uninstall / disable

Stop one target from running again, keep its config and reports:

```sh
systemctl --user disable --now recon-rs@vfc.timer
```

Remove everything this installed, for every target. Note that `disable`/`stop`
(unlike `list-timers`/`journalctl -u`) do **not** accept a glob — loop over the
targets explicitly:

```sh
for env_file in ~/.config/recon-rs/targets/*.env; do
    name="$(basename "${env_file}" .env)"
    systemctl --user disable --now "recon-rs@${name}.timer"
done
rm -rf ~/.config/systemd/user/recon-rs@*.timer.d
rm -f ~/.config/systemd/user/recon-rs@.service ~/.config/systemd/user/recon-rs@.timer
systemctl --user daemon-reload
rm -f ~/.local/bin/recon-cli
rm -rf ~/.config/recon-rs   # also deletes every targets/*.env, config/, and reports/
```

The PostgreSQL database itself (scan history for every target) is untouched by any of
the above — `recon-cli`/`recon-db` never delete anything.
