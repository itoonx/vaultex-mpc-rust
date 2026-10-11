# Host baseline: Guard and monitor hosts

| | |
|---|---|
| **Version** | 0.1-draft, 2026-10-11 |
| **Status** | **PROPOSED.** Not applied to any host yet. The configuration below is reference text; the deployable files will live in `infra/guard/` (WS-07 follow-up). The `sshd` snippet has been checked with `sshd -T` (OpenSSH 10.2). The nftables, systemd and chrony snippets have not been machine-checked yet: run `nft -c -f`, `systemd-analyze verify` and `chronyd -p` on the first real host (T07-6) before relying on them. |
| **Covers** | The Guard host (D-G) and the monitor host (D-M) for Rung 1 and Rung 2 ([ROADMAP](../ROADMAP.md) M7 #4). The operator's host (D-OP) belongs to the operator; §2 still applies to it. |
| **Evidence** | §8: captured at the ceremony, then quarterly, into the evidence pack. |

Vocabulary (domains, keys, severities) is in the [ops README](README.md) §1.

---

## 1. Goals

1. A compromise of **one** credential, vendor or host reaches **one** failure domain only ([threat model](../assurance/THREAT_MODEL_V2.md) AP6, LM7).
2. The Guard host has the smallest possible surface: one service, no chain RPC, no general egress, no agent credential.
3. Every security-relevant setting is checkable: each one has a command whose output goes into the evidence pack.
4. A lost host is rebuilt from this file, the signed release and the ceremony records alone ([RB-5](runbooks.md#rb-5-guard-host-lost-or-rebuilt), [RB-6](runbooks.md#rb-6-monitor-host-lost)).

---

## 2. Failure-domain rules

| ID | Rule |
|---|---|
| FD-1 | D-OP, D-G and D-M run at **three different hosting providers**. A provider shared by two domains collapses them into one |
| FD-2 | **No credential reaches two domains.** That covers console logins, recovery mailboxes and phone numbers, password-manager entries and vaults, SSH key handles, API tokens and TLS client keys. Account recovery is a takeover path, so recovery channels are separated too |
| FD-3 | The monitor's two chain-data providers are run by **different operators**, under accounts the operator domain never uses. Keys under one provider account may share quota, so they also share a failure domain |
| FD-4 | No AI-agent credential exists in D-OP, D-G, D-M or D-C. Agents write code; the owner deploys signed releases by hand |
| FD-5 | Cold keys never touch a networked machine. Transactions travel by file or QR code, and every hash is checked on an air-gapped machine ([ceremonies](../ceremonies/guard.md)) |
| FD-6 | The owner's everyday laptop holds no production credential. Admin work runs from a dedicated device or a separate OS user gated by hardware keys (OD-7) |
| FD-7 | DNS and the public CA system are out of the trust path. mTLS pins certificates; endpoints are configured by IP address or pinned name |
| FD-8 | Data flows one way. Receipts and logs go D-G → D-M (the monitor **pulls** receipts with a read-only certificate). Freeze orders go D-M → D-G. Nothing goes D-M → D-OP except pages. The Guard cannot write into the monitor's state |

Solo-mode limit: one human can still reach every domain. These rules defend against the loss of one credential, vendor or host, not against compromise of the owner (threat model LM7).

---

## 3. Platform and accounts

| ID | Item |
|---|---|
| HB-01 | A minimal image of a current Debian stable or Ubuntu LTS release. The exact release is pinned in the ceremony transcript. No other workload on the host |
| HB-02 | No container runtime: one static binary under systemd. This keeps a root-owned daemon off the host |
| HB-03 | Unattended security upgrades on, with reboots in a declared maintenance window ([RB-14](runbooks.md#rb-14-planned-maintenance)) and never during a drill |
| HB-04 | One cloud account per domain, with its own billing. The root or owner login uses **two hardware security keys** (primary and backup), no SMS, and a recovery mailbox used by no other domain (FD-2) |
| HB-05 | Billing and login alerts on. No long-lived API tokens; if one is unavoidable, it is scoped to one action, stored offline, and never used by CI or agents |
| HB-06 | Break-glass access is the provider's console. Its use is recorded like any login (§7) |

---

## 4. Access: SSH

| ID | Item |
|---|---|
| HB-07 | Public-key login only, with FIDO2 keys (`sk-ssh-ed25519`, OpenSSH ≥ 8.2) that require touch and PIN (`verify-required`). No passwords, no root login, one admin user |
| HB-08 | One FIDO credential per domain, made with a distinct `application` string, on a primary and a backup hardware key. A credential for D-G never logs in to D-M (FD-2) |
| HB-09 | SSH is reachable only from declared admin addresses or through the provider console. No forwarding of agents, ports, X11 or tunnels |
| HB-10 | The host's SSH key fingerprints are read from the provider console at first boot, recorded in the ceremony transcript, and pinned in `known_hosts` on the admin device |

Making the credentials (on the admin device; one per domain, repeated on the backup key):

```sh
ssh-keygen -t ed25519-sk -O verify-required -O application=ssh:vaultex-dg -C dg-admin -f ~/.ssh/vaultex_dg_sk
ssh-keygen -t ed25519-sk -O verify-required -O application=ssh:vaultex-dm -C dm-admin -f ~/.ssh/vaultex_dm_sk
```

`/etc/ssh/sshd_config.d/10-vaultex.conf` (reference):

```text
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AuthenticationMethods publickey
PubkeyAcceptedAlgorithms sk-ssh-ed25519@openssh.com
PubkeyAuthOptions verify-required
AllowUsers vxadmin
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
MaxAuthTries 3
LoginGraceTime 30
```

---

## 5. Network

| ID | Item |
|---|---|
| HB-11 | nftables, **default deny** in both directions, with an explicit allowlist per host (§9) |
| HB-12 | The Guard API accepts connections only from the D-OP and D-M addresses, and only with a pinned client certificate per role (`op`, `mon`). The admin surface (policy install, unfreeze, receipt-key rotation) is a local Unix socket on the Guard host, never a network port |
| HB-13 | **The Guard has no chain-RPC egress.** It decides from the bytes it is given, and its only outbound traffic is time, OS updates, log upload to D-M and, if ADR-17 picks cloud custody, the key service's endpoint (preferably a private endpoint) |
| HB-14 | IPv6 is either disabled or given the same rules, plus ICMPv6 neighbour discovery |

`/etc/nftables.conf` for the Guard host (reference; the addresses are RFC 5737 documentation values):

```text
#!/usr/sbin/nft -f
flush ruleset

define ADMIN_SSH   = { 192.0.2.10 }                  # declared admin addresses
define CALLERS     = { 198.51.100.20, 203.0.113.30 } # D-OP submitter, D-M monitor
define MONITOR     = { 203.0.113.30 }                # log upload target
define NTS         = { 192.0.2.123, 192.0.2.124 }    # pinned NTS servers
define RESOLVER    = { 192.0.2.53 }
define MIRRORS     = { 192.0.2.80 }                  # OS package mirror
define GUARD_PORT  = 8443
define JOURNAL_RX  = 19532

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop
        iifname "lo" accept
        ip saddr $ADMIN_SSH tcp dport 22 accept
        ip saddr $CALLERS tcp dport $GUARD_PORT accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
    chain output {
        type filter hook output priority filter; policy drop;
        ct state established,related accept
        oifname "lo" accept
        ip daddr $NTS tcp dport 4460 accept              # NTS key establishment
        ip daddr $NTS udp dport 123 accept
        ip daddr $RESOLVER meta l4proto { tcp, udp } th dport 53 accept
        ip daddr $MIRRORS tcp dport { 80, 443 } accept   # packages are signed by the distribution
        ip daddr $MONITOR tcp dport $JOURNAL_RX accept   # journal upload to D-M
    }
}
```

The monitor host uses the same structure, with the differences in §9.

---

## 6. The service unit

| ID | Item |
|---|---|
| HB-15 | A dedicated system user per service. State lives only under `/var/lib/vaultex-<service>` (`StateDirectory=`); the rest of the file system is read-only to the service |
| HB-16 | Sandboxing as below. `systemd-analyze security` output is stored in the transcript; target exposure ≤ 2.0 (ESTIMATE) |
| HB-17 | Secrets reach the service only through `LoadCredentialEncrypted=`: never through environment variables, command lines or plain files. Core dumps are off |

`/etc/systemd/system/vaultex-guard.service` (reference; the binary's flags are defined by T06-5, and the monitor's unit differs only in names, credentials and `ExecStart`):

```ini
[Unit]
Description=Vaultex Guard (additive co-signer)
Wants=network-online.target time-sync.target
After=network-online.target time-sync.target

[Service]
Type=simple
User=vaultex-guard
Group=vaultex-guard
# Flags are placeholders until T06-5 defines them.
ExecStart=/opt/vaultex/bin/vaultex-guard --config /etc/vaultex/guard.toml
Restart=on-failure
RestartSec=5s
StateDirectory=vaultex-guard
StateDirectoryMode=0700
UMask=0077
LimitCORE=0
# One line per secret; the file is sealed with systemd-creds (HB-18).
LoadCredentialEncrypted=receipt-key:/etc/credstore.encrypted/receipt-key.cred

NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
```

If the service fails under this filter, the journal names the blocked call. Relax it narrowly and record the change. A USB HSM (an ADR-17 option) needs `PrivateDevices=no` plus a device allowlist.

---

## 7. Keys at rest, time, storage, integrity and logs

### 7.1 Keys at rest

| ID | Item |
|---|---|
| HB-18 | Software keys on a host (the receipt key with file custody; the monitor's freeze, ack and evidence keys; mTLS client keys; provider API keys) are sealed with `systemd-creds`, bound to the host's TPM2 where the VM offers one, and to the host key otherwise. The plaintext exists only in the service's private credentials directory while it runs |
| HB-19 | Key material is never in a provider snapshot or backup in plaintext. Sealed credentials are bound to the host, so a snapshot restored elsewhere cannot open them; that is why recovery goes through the ceremonies, not through snapshots |
| HB-20 | The Guard key itself follows ADR-17: an encrypted file, a non-exportable cloud KMS key, or an HSM. Its ceremony is CER-2 |

Sealing a credential (on the host, from a key file created in a RAM-backed directory and deleted right after):

```sh
systemd-creds encrypt --with-key=auto --name=receipt-key /run/vx-ceremony/receipt-key /etc/credstore.encrypted/receipt-key.cred
```

### 7.2 Time

| ID | Item |
|---|---|
| HB-21 | chrony with **at least two NTS-authenticated sources from different operators**, `authselectmode require` and `minsources 2`. Remove the distribution's default `pool` and `sourcedir` lines |
| HB-22 | The NTS server names are pinned in `/etc/hosts`, so a DNS failure cannot stop time sync (the certificates are still checked). An offset above 500 ms raises a Sev-2 alert (rule MR-20). The kernel's clock checks are the backstop ([threat model](../assurance/THREAT_MODEL_V2.md) AP5) |

`/etc/chrony/chrony.conf` (reference; add a third NTS source from another operator where available):

```text
server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
authselectmode require
minsources 2
ntsdumpdir /var/lib/chrony
makestep 1 3
rtcsync
```

### 7.3 Storage and backups

| ID | Item |
|---|---|
| HB-23 | Provider disk encryption on. The state directory is on its own volume |
| HB-24 | Configuration files hold no secret values and are backed up to the private evidence store with their SHA-256 |
| HB-25 | The Guard's receipt journal is restorable from the monitor's verified, anchored copy ([RB-5](runbooks.md#rb-5-guard-host-lost-or-rebuilt)); the monitor's own journal goes into every monthly evidence pack |

### 7.4 Release integrity

| ID | Item |
|---|---|
| HB-26 | Only releases whose signature and provenance verify **on the host** are installed (T02-12, M7 #6). The binary's SHA-256 is recorded at every install |
| HB-27 | The Guard reports its running binary's SHA-256; the monitor compares it with the pinned release digest (MR-20). The pin is updated before an upgrade, never after ([RB-14](runbooks.md#rb-14-planned-maintenance)) |
| HB-28 | Until signed releases exist (T02-12), hosts run testnet only, from binaries the owner built from a reviewed tag on two machines with equal digests |

### 7.5 Logs and the login canary

| ID | Item |
|---|---|
| HB-29 | journald is persistent, with a size cap. The Guard host uploads `sshd` and service logs to the monitor host (`systemd-journal-upload` to `systemd-journal-remote`), which accepts them from that one address only. The upload path can append logs; it cannot touch the monitor's state |
| HB-30 | **Any login outside a declared maintenance window pages** (MR-20, Sev-2). Windows are declared to the monitor in advance ([RB-14](runbooks.md#rb-14-planned-maintenance)) |

---

## 8. Checklist evidence

Captured at the ceremony (CER-0, CER-6), after every rebuild, and then quarterly. Each output's SHA-256 goes into the transcript; the outputs go into the evidence pack under `host/`.

| Check | Command | Expected |
|---|---|---|
| Firewall | `nft list ruleset` | Equal to the reviewed file |
| SSH | `sshd -T` | `passwordauthentication no`, `kbdinteractiveauthentication no`, `permitrootlogin no`, `pubkeyauthoptions verify-required`, only `sk-ssh-ed25519@openssh.com` accepted |
| Unit sandbox | `systemd-analyze security vaultex-<service>.service` | Exposure ≤ 2.0 (ESTIMATE target) |
| Listening sockets | `ss -tlnup` | Guard: `sshd` and the Guard port. Monitor: `sshd` and the journal receiver. Plus chronyd on localhost |
| Time | `chronyc -N authdata` and `chronyc tracking` | Every source authenticated with NTS; offset well under 500 ms |
| Binary | `sha256sum /opt/vaultex/bin/vaultex-<service>` | Equal to the signed release digest |
| Accounts | `getent passwd` (login shells only) | The admin user only, plus root locked |
| Packages | `dpkg-query -W` digest | Recorded; differences explained by upgrades |
| Optional scan | Lynis or a CIS Level 1 benchmark | No unexplained high-severity finding |

**Quarterly domain audit** (threat model AP6). The owner checks, by label, that every account, recovery channel, hardware key and password-manager entry still belongs to exactly one domain, and records a signed one-line attestation in the evidence pack. The inventory itself stays private.

---

## 9. Per-host differences

| | Guard host (D-G) | Monitor host (D-M) |
|---|---|---|
| Inbound | SSH from admin addresses; the Guard API from the D-OP and D-M addresses only | SSH from admin addresses; journal upload from the Guard host only. No service port |
| Outbound | Time, resolver, OS mirrors, journal upload to D-M; the key service only if ADR-17 picks cloud custody. **No chain RPC** | Time, resolver, OS mirrors, HTTPS to its two chain providers, the Guard API, the alert services and the dead-man check |
| Keys | Guard key (ADR-17), receipt key, server TLS key | Freeze key, evidence key, ack key (OD-1), mTLS client key, provider API keys (sent only in the provider's header, never in a URL) |
| State | Receipt journal; replay, velocity and freeze state (T06-5) | Cursors, the anchored receipt copy, the alert journal |
| Unattended restart | Yes with a sealed credential or cloud custody. A passphrase typed at start needs a human | Yes |

ponytail: hosted chain providers often change addresses, so the monitor may allow outbound HTTPS to any address if its providers' addresses are not stable. Record that exception in the transcript. The monitor has no inbound service, and its trust in the providers comes from comparing two of them, not from the network path.
