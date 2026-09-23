# Proposal: Generalize OpenConnect Password Auth to support anyconnect (and other protocols)

## Status

Implemented locally. See "Applied diff" section at the bottom for the exact patch.

## Context

Users on anyconnect-based VPNs (Cisco AnyConnect, and other `openconnect --protocol=anyconnect` gateways) whose gateway certificate is expired, self-signed, or otherwise untrusted **cannot complete the connection through DMS**. The same VPN works fine through `nmcli --ask` because the terminal shows openconnect's cert prompt.

Reproduction:
1. Have a profile with `vpn.protocol=anyconnect`, `vpn.authtype=password`.
2. Gateway presents a cert the system trust store rejects (expired is the common case).
3. Click the profile in Control Center → VPN.
4. Password prompt appears, user enters password.
5. NM starts `openconnect --non-inter`.
6. openconnect prints:
   ```
   SSL certificate verification failed: Certificate has expired
   To trust this server, add this to your command line:
       --servercert pin-sha256:hHohMy4jzxWJSK/fUPaCzkNunIX05Jsu2zCnSeGGvTA=
   ```
   and blocks on `fgets(stdin)`.
7. NM times out after ~15 s with:
   ```
   vpn[...]: final secrets request failed to provide sufficient secrets
   ```

The exact same profile with Fortinet (`vpn.protocol=fortinet`) **does** get the DMS cert-acceptance dialog. This is the target behavior for anyconnect.

## Root Cause

Two places in the code path are hardcoded to `fortinet` and need to be generalized.

### 1. `detectVPNAuthAction` short-circuits non-fortinet to no pre-auth

`core/internal/server/network/backend_networkmanager_vpn.go:462-478`

```go
case strings.Contains(serviceType, "openconnect"):
    protocol := data["protocol"]
    if needsExternalBrowserAuth(protocol, data["authtype"], data["username"], data) {
        switch protocol {
        case "gp":
            return "gp_saml"
        case "fortinet":
            return "fortinet_saml"
        default:
            log.Infof("[VPN] External browser auth detected for protocol '%s' but only GlobalProtect (gp) and Fortinet are currently supported", protocol)
        }
    }
    if protocol == "fortinet" && data["authtype"] == "password" {
        return "openconnect_password"
    }
```

For `protocol=anyconnect`, this returns `""`, so `ConnectVPN` skips pre-auth entirely and calls `nm.ActivateConnection` directly. Any cert handling lives inside `handleOpenConnectPasswordAuth`, which is now never called.

### 2. `runOpenConnectPasswordAuth` refuses non-fortinet and hardcodes the protocol flag

`core/internal/server/network/backend_networkmanager_gp_saml.go:146-182`

```go
func runOpenConnectPasswordAuth(ctx context.Context, data map[string]string, username, password, serverCert string) (*openConnectAuthResult, error) {
    if data["protocol"] != "fortinet" {
        return nil, fmt.Errorf("only Fortinet password authentication is supported")
    }
    ...
    args := []string{
        "--protocol=fortinet",
        ...
    }
```

Even if the caller routed anyconnect through `handleOpenConnectPasswordAuth`, this function would refuse.

### 3. Existing cert-rotation logic is already protocol-agnostic

`core/internal/server/network/backend_networkmanager_vpn.go:580-618`

```go
auth, err := runOpenConnectPasswordAuth(ctx, data, username, password, serverCert)
persistentSecrets := map[string]string{}
var authErr *openConnectAuthError
if err != nil && errors.As(err, &authErr) && authErr.serverCert != "" && authErr.serverCert != serverCert {
    reason := "server-certificate"
    if serverCert != "" {
        reason = "server-certificate-changed"
    }
    token, promptErr := b.promptBroker.Ask(ctx, PromptRequest{
        Name:           connName,
        ConnType:       "vpn",
        VpnService:     vpnServiceType,
        SettingName:    "vpn",
        Hints:          []string{authErr.serverCert},
        Reason:         reason,
        ConnectionId:   connName,
        ConnectionUuid: targetUUID,
        ConnectionPath: string(targetConn.GetPath()),
    })
    ...
    auth, err = runOpenConnectPasswordAuth(ctx, data, username, password, authErr.serverCert)
    if err == nil {
        persistentSecrets["certificate:" + data["gateway"]] = authErr.serverCert
    }
}
```

The pin-sha256 extraction, the prompt, the retry, and the "save pin under `certificate:<gateway>`" persistence are all already generic. They just never run for anyconnect.

The QML side (`WifiPasswordModal.qml`) already handles the `server-certificate` / `server-certificate-changed` reasons.

## Applied Diff

Three files, 90 insertions, 9 deletions.

```
core/internal/server/network/backend_networkmanager_gp_saml.go |  7 +-
core/internal/server/network/backend_networkmanager_vpn.go     |  2 +-
core/internal/server/network/backend_networkmanager_vpn_test.go | 90 ++++++++++++++++++-
```

### Edit 1 — `core/internal/server/network/backend_networkmanager_vpn.go`

In `detectVPNAuthAction`, drop the `protocol == "fortinet"` check.

```diff
 	case strings.Contains(serviceType, "openconnect"):
 		protocol := data["protocol"]
 		if needsExternalBrowserAuth(protocol, data["authtype"], data["username"], data) {
 			switch protocol {
 			case "gp":
 				return "gp_saml"
 			case "fortinet":
 				return "fortinet_saml"
 			default:
 				log.Infof("[VPN] External browser auth detected for protocol '%s' but only GlobalProtect (gp) and Fortinet are currently supported", protocol)
 			}
 		}
-		if protocol == "fortinet" && data["authtype"] == "password" {
+		if data["authtype"] == "password" {
 			return "openconnect_password"
 		}
```

### Edit 2 — `core/internal/server/network/backend_networkmanager_gp_saml.go`

Replace the fortinet-only rejection with a generic protocol pass-through.

```diff
 func runOpenConnectPasswordAuth(
 	ctx context.Context,
 	data map[string]string,
 	username, password, serverCert string,
 ) (*openConnectAuthResult, error) {
-	if data["protocol"] != "fortinet" {
-		return nil, fmt.Errorf("only Fortinet password authentication is supported")
+	protocol := data["protocol"]
+	if protocol == "" {
+		return nil, fmt.Errorf("OpenConnect protocol is empty")
 	}
 	gateway := data["gateway"]
 	if gateway == "" {
 		return nil, fmt.Errorf("OpenConnect gateway is empty")
 	}
 	if username == "" || password == "" {
 		return nil, fmt.Errorf("OpenConnect username and password are required")
 	}

 	args := []string{
-		"--protocol=fortinet",
+		"--protocol=" + protocol,
 		"--user=" + username,
 		"--passwd-on-stdin",
 		"--non-inter",
 	}
```

### Edit 3 — `core/internal/server/network/backend_networkmanager_vpn_test.go`

Renamed and expanded `TestDetectVPNAuthAction_Fortinet` to `TestDetectVPNAuthAction_OpenConnectPassword`:
- Regression guard for fortinet
- New cases for anyconnect / juniper-ssl / cisco
- SAML branch still returns `fortinet_saml`
- Non-password authtypes without SAML still fall through to no pre-auth

Added `TestOpenConnectCertificateConfirmation_AnyConnect` using a shell script as an `openconnect` stub. The stub asserts `--protocol=anyconnect` is passed, verifies `--servercert=pin-sha256:ANY-CONNECT-PIN` is passed on retry, and validates the prompt reason + persisted pin.

## End-to-end behavior after the change

1. User clicks a `protocol=anyconnect, authtype=password` profile in VPN popout.
2. `detectVPNAuthAction` returns `"openconnect_password"` (same as fortinet today).
3. `handleOpenConnectPasswordAuth` runs:
   - Reads `password` and `certificate:<gateway>` / `gwcert` from stored secrets.
   - If either is missing, prompts user for username/password via `WifiPasswordModal` (already wired).
   - Runs `openconnect --protocol=anyconnect --user=... --passwd-on-stdin --non-inter [--servercert=...] --authenticate <gateway>`.
4. If openconnect fails with `pin-sha256:...` in output, the existing error branch:
   - Prompts `WifiPasswordModal` with `reason="server-certificate"` (first time) or `"server-certificate-changed"` (rotation).
   - Retries with `--servercert=<pin>`.
   - On success, queues `certificate:<gateway> = pin-sha256:...` in `pendingVPNSave`.
5. `ConnectVPN` stores the resulting `openConnectAuthResult` in `cachedOpenConnectAuth` and calls `nm.ActivateConnection`.
6. NM's openconnect plugin calls the secret agent for `{cookie, gateway, gwcert}` — `agent.GetSecrets` returns the cached values via `buildOpenConnectSecretsResponse`.
7. Once activation reaches state=2, `saveVPNCredentials` persists the username (if entered), the password (if save is checked), and the pin.
8. Next connection uses the stored pin with `--servercert=pin-sha256:...` and openconnect skips system trust store, so the expired cert is accepted silently.

The user-visible flow now mirrors `nmcli --ask` minus the terminal prompt:

```
[VPN krb] Password: ******                          ← WifiPasswordModal (existing)
[VPN krb] Untrusted VPN certificate                  ← WifiPasswordModal (existing, reason=server-certificate)
         Server fingerprint:
           pin-sha256:hHohMy4jzxWJSK/fUPaCzkNunIX05Jsu2zCnSeGGvTA=
         Only continue if you recognize this server certificate fingerprint.
         [Trust]   [Cancel]
[VPN krb] ✓ Connected                                ← ToastService
```

## Local Test Commands

### Prerequisites

```bash
cd /home/virs/code/DankMaterialShell
# Make sure you're on the branch with the patch applied.
git diff --stat   # should show the 3 files above
```

### Unit tests (fast, no side effects)

```bash
cd core

# Fastest: only the touched functions.
go test ./internal/server/network/... -run "OpenConnect|DetectVPNAuthAction|Fortinet" -v

# Full network package (also fast).
go test ./internal/server/network/...

# Whole core (slower; ~1-2 min).
go test ./...

# Static analysis.
go vet ./...
```

Expected: `PASS` for every target, `go vet` prints nothing.

### Rebuild and run DMS from source

```bash
cd /home/virs/code/DankMaterialShell

# Build.
make dev

# Stop the running DMS (if it was installed via `make install` or distro package).
systemctl --user stop dms

# Run against the local source tree (overrides installed shell if --session isn't passed).
# Logs go to stdout — pipe to a file if you want to grep them.
./core/bin/dms run -c ./quickshell 2>&1 | tee /tmp/dms-source.log
```

To run it as your usual user service (backgrounded, restarted by systemd on failure):

```bash
# Point the systemd unit at the source-tree binary and shell.
mkdir -p ~/.config/systemd/user/dms-run.d
cat > ~/.config/systemd/user/dms-run.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/home/virs/code/DankMaterialShell/core/bin/dms run -c /home/virs/code/DankMaterialShell/quickshell --session
EOF

systemctl --user daemon-reload
systemctl --user restart dms
journalctl --user -u dms -f
```

To disable the override later, run `rm ~/.config/systemd/user/dms-run.d/override.conf && systemctl --user daemon-reload && systemctl --user restart dms`.

### Manual end-to-end VPN test

```bash
# Pick a fresh name so we don't clobber a real profile.
NAME=vpn-anyconnect-test

# Add a minimal anyconnect profile. Replace the gateway with your own.
nmcli connection add type vpn ifname anyconnect0 \
    con-name "$NAME" \
    vpn.service-type org.freedesktop.NetworkManager.openconnect.vpnc \
    vpn.protocol anyconnect \
    vpn.authtype password \
    vpn.gateway "61.175.123.146:64433" \
    vpn.cookie-flags 2 vpn.gateway-flags 2 vpn.gwcert-flags 2

# Connect. Watch for two prompts in sequence:
#   1) Password
#   2) Untrusted VPN certificate → Trust
dms ipc call network.vpn.connect "{\"uuidOrName\":\"$NAME\",\"singleActive\":false}"

# Confirm the pin was persisted.
UUID=$(nmcli -t -f UUID connection show | grep -i "vpn-anyconnect-test" | cut -d: -f1)
nmcli --show-secrets connection show "$UUID" | grep -Ei 'certificate|gwcert'
# Expected: certificate:<gateway> = pin-sha256:hHohMy4jzxWJSK/...

# Disconnect and reconnect. Should NOT re-prompt for the cert.
dms ipc call network.vpn.disconnect "{\"uuidOrName\":\"$UUID\"}"
dms ipc call network.vpn.connect "{\"uuidOrName\":\"$UUID\",\"singleActive\":false}"
```

### Log tail while reproducing

```bash
# DMS-side (with the override above, this streams live):
journalctl --user -u dms -f | grep -Ei 'vpn|openconnect|secret|fortinet|gp-saml'

# NM-side:
sudo journalctl -u NetworkManager -f | grep -Ei 'vpn|openconnect|secret'
```

## Rollback

The change is 3 files with no schema, config, or migration. Two ways to revert.

### Option A: full `git revert` / `git checkout`

```bash
cd /home/virs/code/DankMaterialShell

# If you staged or committed the change:
git revert HEAD            # uncommits the last commit
# or
git checkout HEAD~1 -- core/internal/server/network/backend_networkmanager_vpn.go \
                        core/internal/server/network/backend_networkmanager_gp_saml.go \
                        core/internal/server/network/backend_networkmanager_vpn_test.go

# If the change is unstaged (as it is now):
git checkout -- core/internal/server/network/backend_networkmanager_vpn.go \
                core/internal/server/network/backend_networkmanager_gp_saml.go \
                core/internal/server/network/backend_networkmanager_vpn_test.go
```

Verify:
```bash
git diff --stat           # empty
git status                # clean
```

### Option B: manually re-apply the original code

If you want to keep the tests but revert only the production change:

```bash
# Restore the fortinet-only check in runOpenConnectPasswordAuth.
cd core/internal/server/network/backend_networkmanager_gp_saml.go
# Revert the hunk shown in "Edit 2" above.

# Restore the protocol == "fortinet" && in detectVPNAuthAction.
cd core/internal/server/network/backend_networkmanager_vpn.go
# Revert the hunk shown in "Edit 1" above.

# Tests will fail after this — also revert the test file, or remove the two
# new test functions manually.
```

### Undo the systemd override (if applied during testing)

```bash
rm ~/.config/systemd/user/dms-run.d/override.conf
systemctl --user daemon-reload
systemctl --user restart dms

# Confirm the installed binary is back in use:
systemctl --user cat dms | grep ExecStart
# Expected: ExecStart=/usr/bin/dms run --session
```

### Undo the test profile

```bash
nmcli connection delete vpn-anyconnect-test
```

## Risk

- **AnyConnect one-time tokens (stoken):** The user's profile uses `stoken_source=disabled` (see `nmcli connection show`). OpenConnect 9+ treats `--token=...` or `--stoken-source=...` for anyconnect; DMS doesn't set either today, which is a pre-existing gap that this PR doesn't worsen. If a user's gateway requires STOK, `--passwd-on-stdin` still works but the profile needs an explicit `--stoken-source`. Out of scope here.
- **Personal cert (`authtype=cert`):** `detectVPNAuthAction` doesn't route cert-auth to any pre-auth path today, so no behavior change.
- **Juniper / Cisco legacy:** Also use openconnect with `--protocol=juniper-ssl` or `--protocol=cisco`. The same generalized path now applies. Existing pin-sha256 extraction from stdout is protocol-agnostic in openconnect, so the retry flow should just work.
- **Wrong protocol string:** If someone imports a profile with `vpn.protocol=` set to something openconnect doesn't know, the CLI will now fail with a clear `openconnect: unknown protocol` error instead of the previous "only Fortinet password authentication is supported" error. Strictly better diagnostics.

## Alternatives considered

- **Prompt user for `gwcert` in the secret agent's Phase 6.** This is what the NM secret agent protocol allows, but the field is a `pin-sha256:` value that ordinary users can't type. DMS's `WifiPasswordModal` doesn't have a `pin-sha256:` editor. Would require a new modal.
- **Add a new `vpn.protocol=anyconnect` branch that shells out to `openconnect --list-countries` to probe.** Overkill; we already know the protocol from the profile.
- **Pass `--allow-insecure-crypto` for anyconnect.** Would silently accept every cert regardless of validity. Not acceptable as a default; matches the GP SAML path's current behavior but that's a separate concern.

## Follow-ups (out of scope)

- GP SAML path (`runGlobalProtectSAMLAuth`) skips cert verification entirely by using `--allow-insecure-crypto`. It should adopt `probeGatewayCert` + `resolveFortinetCertTrust` the way `authenticateFortinetSAML` does. Tracked separately.
- `WifiPasswordModal` should show a copyable fingerprint pill for `server-certificate` prompts — the current `[fingerprint]` display is plain text and hard to select on touch devices.
