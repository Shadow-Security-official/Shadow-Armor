package harden

import (
	"context"
	"fmt"
	"os"
	osuser "os/user"
	"sort"
	"strconv"
	"strings"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/target"
)

// GuardResult is the outcome of one safety guard.
type GuardResult struct {
	Name    string
	Control string
	OK      bool
	Detail  string
}

// account is an interactive account of the target, as the guards see it.
type account struct {
	Name     string
	UID      int
	Key      bool // can log in with an SSH key
	Sudo     bool // may run commands through sudo
	Password bool // has a usable password hash
}

// facts is what the guards need to know about the target, read once.
type facts struct {
	Accounts   []account
	PermitRoot string // effective sshd PermitRootLogin ("" when sshd is absent)
	Session    string // who is running the harden
	OverSSH    bool   // ... through an SSH login
}

func (f facts) account(name string) (account, bool) {
	for _, a := range f.Accounts {
		if a.Name == name {
			return a, true
		}
	}
	return account{}, false
}

// admins are accounts other than root that can log in with a key and use sudo.
func (f facts) admins() []string {
	var out []string
	for _, a := range f.Accounts {
		if a.UID != 0 && a.Key && a.Sudo {
			out = append(out, a.Name)
		}
	}
	return out
}

func (f facts) rootOverSSH() bool { return f.Session == "root" && f.OverSSH }

// accountsScript lists interactive accounts as name|uid|key|sudo|password.
// Keys are looked up where sshd looks (AuthorizedKeysFile, %h/%u expanded);
// an AuthorizedKeysCommand counts as a key source for everybody.
const accountsScript = `
min=$(awk '/^[[:space:]]*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null); min=${min:-1000}
akf=$(sshd -T 2>/dev/null | awk '/^authorizedkeysfile /{$1=""; print}')
akc=$(sshd -T 2>/dev/null | awk '/^authorizedkeyscommand /{print $2}')
[ -n "$akf" ] || akf=".ssh/authorized_keys .ssh/authorized_keys2"
awk -F: -v min="$min" '($3>=min || $3==0) && $7 !~ /(nologin|false)$/ && $1!="nobody" {print $1":"$3":"$6}' /etc/passwd |
while IFS=: read -r n u h; do
  k=0
  for p in $akf; do
    f=$(printf '%s' "$p" | sed "s|%h|$h|g; s|%u|$n|g; s|%%|%|g")
    case "$f" in /*) ;; *) f="$h/$f" ;; esac
    [ -s "$f" ] && grep -qvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null && k=1
  done
  [ -n "$akc" ] && [ "$akc" != none ] && k=1
  s=0
  if [ "$u" != 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n -l -U "$n" 2>/dev/null | grep -q 'may run the following'; then s=1; fi
  p=0
  case "$(awk -F: -v n="$n" '$1==n {print $2}' /etc/shadow 2>/dev/null)" in ''|'!'*|'*'*) ;; *) p=1 ;; esac
  echo "$n|$u|$k|$s|$p"
done
`

func readFacts(ctx context.Context, t *target.Target) facts {
	var f facts
	out, _ := t.Output(ctx, accountsScript, true)
	for _, l := range strings.Split(out, "\n") {
		p := strings.Split(strings.TrimSpace(l), "|")
		if len(p) != 5 {
			continue
		}
		uid, _ := strconv.Atoi(p[1])
		f.Accounts = append(f.Accounts, account{Name: p[0], UID: uid, Key: p[2] == "1", Sudo: p[3] == "1", Password: p[4] == "1"})
	}
	f.PermitRoot, _ = t.Output(ctx, `sshd -T 2>/dev/null | awk '/^permitrootlogin /{print $2}'`, true)
	if f.PermitRoot == "without-password" {
		f.PermitRoot = "prohibit-password"
	}
	switch t.Kind {
	case target.SSH:
		f.Session, _ = t.Output(ctx, "id -un", false)
		f.OverSSH = true
	case target.Local:
		f.Session, f.OverSSH = localSession()
	default:
		f.Session = "root"
	}
	return f
}

// localSession names who logged in (the login uid survives sudo) and whether
// that login came through sshd.
func localSession() (string, bool) {
	name := ""
	if b, err := os.ReadFile("/proc/self/loginuid"); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" && id != "4294967295" {
			if u, err := osuser.LookupId(id); err == nil {
				name = u.Username
			}
		}
	}
	if name == "" {
		name = os.Getenv("SUDO_USER")
	}
	if name == "" {
		if u, err := osuser.Current(); err == nil {
			name = u.Username
		}
	}
	over := os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != ""
	for pid, i := os.Getppid(), 0; !over && pid > 1 && i < 64; i++ {
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			break
		}
		if strings.HasPrefix(strings.TrimSpace(string(comm)), "sshd") {
			over = true
			break
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			break
		}
		s := string(stat)
		fields := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
		if len(fields) < 2 {
			break
		}
		pid, _ = strconv.Atoi(fields[1])
	}
	return name, over
}

// Guards runs the safety checks declared by the plan's controls, plus the
// ones implied by their actions (package removals). A failed guard means
// applying that control could cut access to the host or break what runs on it.
func Guards(ctx context.Context, t *target.Target, p *Plan) []GuardResult {
	var out []GuardResult
	var f *facts
	get := func() facts {
		if f == nil {
			v := readFacts(ctx, t)
			f = &v
		}
		return *f
	}
	inPlan := map[string]bool{}
	for _, it := range p.Items {
		inPlan[it.Control] = true
	}
	for _, it := range p.Items {
		names := append([]string{}, it.Guards...)
		for _, a := range it.Actions {
			if a["kind"] == "packages_absent" {
				names = append(names, "removal_contained")
				break
			}
		}
		for _, g := range names {
			r := GuardResult{Name: g, Control: it.Control, OK: true}
			switch g {
			case "ssh_not_root_session":
				fs := get()
				if fs.rootOverSSH() {
					r.OK = false
					r.Detail = "you are logged in over SSH as root: the next root login would be refused. Log in as an administrator account and use sudo, or run it from the console"
				} else {
					r.Detail = "session: " + sessionLabel(fs)
				}
			case "admin_account_ready":
				fs := get()
				if ad := fs.admins(); len(ad) > 0 {
					r.Detail = "can log in with a key and use sudo: " + strings.Join(ad, ", ")
				} else {
					r.OK = false
					r.Detail = "no account other than root can log in with an SSH key and use sudo: create one first (useradd -m -G sudo <name>, add its key), or keep root with keys only (level 1)"
				}
			case "root_key_login":
				r.OK, r.Detail = rootKeyLogin(get())
			case "ssh_key_access":
				r.OK, r.Detail = keyAccess(get(), inPlan["SA-06.21"])
			case "su_has_alternative":
				r.OK, r.Detail = suAlternative(get())
			case "firewall_safe":
				r.OK, r.Detail = firewallSafe(ctx, t, it)
			case "forwarding_unused":
				r.OK, r.Detail = forwardingUnused(ctx, t)
			case "removal_contained":
				r.OK, r.Detail = removalContained(ctx, t, it)
			default:
				r.Detail = "unknown guard, skipped"
			}
			out = append(out, r)
		}
	}
	return out
}

func sessionLabel(f facts) string {
	switch {
	case f.Session == "":
		return "unknown"
	case f.OverSSH:
		return f.Session + " over SSH"
	}
	return f.Session + " (not over SSH)"
}

// rootKeyLogin: refusing root passwords must leave a way in.
func rootKeyLogin(f facts) (bool, string) {
	root, ok := f.account("root")
	switch {
	case !ok:
		return true, "root has no login shell"
	case root.Key:
		return true, "root logs in with an SSH key: key logins keep working"
	case !root.Password:
		return true, "root has no usable password: nothing changes for its logins"
	case len(f.admins()) > 0 && !f.rootOverSSH():
		return true, "root has no SSH key, but " + strings.Join(f.admins(), ", ") + " can log in with a key and use sudo"
	}
	return false, "root logs in with a password and has no SSH key: add your public key to /root/.ssh/authorized_keys first, or create an administrator account with a key and sudo"
}

// keyAccess: disabling passwords must leave somebody able to log in, the
// person running the harden included.
func keyAccess(f facts, rootRefused bool) (bool, string) {
	var keyed, pwOnly []string
	for _, a := range f.Accounts {
		rootOK := a.UID != 0 || (f.PermitRoot != "no" && !rootRefused)
		switch {
		case a.Key && rootOK:
			keyed = append(keyed, a.Name)
		case !a.Key && a.Password && rootOK:
			pwOnly = append(pwOnly, a.Name)
		}
	}
	if f.OverSSH && f.Session != "" {
		if a, ok := f.account(f.Session); ok && !a.Key {
			return false, "you (" + f.Session + ") are logged in over SSH without an authorized key: add yours first, or you will not get back in"
		}
	}
	if len(keyed) == 0 {
		return false, "no account can log in with an SSH key: disabling passwords would lock everybody out of SSH"
	}
	d := "key logins: " + strings.Join(keyed, ", ")
	if len(pwOnly) > 0 {
		d += " · password-only accounts losing SSH access: " + strings.Join(pwOnly, ", ")
	}
	return true, d
}

// suAlternative: restricting su must not remove the only way to root.
func suAlternative(f facts) (bool, string) {
	var users, sudoers []string
	for _, a := range f.Accounts {
		if a.UID == 0 {
			continue
		}
		users = append(users, a.Name)
		if a.Sudo {
			sudoers = append(sudoers, a.Name)
		}
	}
	switch {
	case len(users) == 0:
		return true, "only root has a login shell: nobody relies on su"
	case len(sudoers) > 0:
		return true, "sudo users: " + strings.Join(sudoers, ", ")
	}
	return false, strings.Join(users, ", ") + " cannot use sudo: su is their only way to root. Grant sudo first (usermod -aG sudo <name>)"
}

// firewallSafe: a default-deny firewall must not fight another one, nor cut
// a service that listens now.
func firewallSafe(ctx context.Context, t *target.Target, it Item) (bool, string) {
	out, _ := t.Output(ctx, `
active() { systemctl is-active --quiet "$1" 2>/dev/null; }
for u in kubelet k3s k3s-agent rke2-server rke2-agent k0scontroller k0sworker; do active "$u" && echo "block:Kubernetes node ($u)"; done
{ [ -d /etc/pve ] || command -v pveversion >/dev/null 2>&1; } && echo "block:Proxmox VE host (use the Proxmox firewall)"
for u in shorewall csf firehol; do active "$u" && echo "block:managed by $u"; done
if command -v apt-get >/dev/null 2>&1; then active firewalld && echo "block:managed by firewalld"; else active ufw && echo "block:managed by ufw"; fi
{ active docker || active podman; } && echo "note:ports published by Docker/Podman bypass this firewall"
sshd -T 2>/dev/null | awk '/^port /{print "port:"$2"/tcp"}'
ss -H -tulnp 2>/dev/null | sed 's/^/ss:/'
lr=$(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null); echo "range:$lr"
`, true)
	var blocks, notes, ssLines []string
	ports := []string{"22/tcp"}
	lo, hi := 32768, 60999
	for _, l := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(l, ":")
		switch k {
		case "block":
			blocks = append(blocks, v)
		case "note":
			notes = append(notes, v)
		case "port":
			ports = append(ports, v)
		case "ss":
			ssLines = append(ssLines, v)
		case "range":
			if fs := strings.Fields(v); len(fs) == 2 {
				a, _ := strconv.Atoi(fs[0])
				b, _ := strconv.Atoi(fs[1])
				if a > 0 && b >= a {
					lo, hi = a, b
				}
			}
		}
	}
	for _, a := range it.Actions {
		if a["kind"] != "firewall" {
			continue
		}
		switch v := a["allow_tcp"].(type) {
		case []any:
			for _, x := range v {
				ports = append(ports, fmt.Sprintf("%v/tcp", x))
			}
		}
	}
	ports = append(ports, ListeningPorts(ssLines, lo, hi)...)
	if len(blocks) > 0 {
		return false, strings.Join(blocks, "; ") + ": a second firewall would conflict"
	}
	d := "ports kept open: " + strings.Join(sortPorts(ports), ", ")
	if len(notes) > 0 {
		d += " · " + strings.Join(notes, "; ")
	}
	return true, d
}

// ListeningPorts turns `ss -H -tulnp` lines into "port/proto" for sockets
// reachable from the network; UDP sockets on an ephemeral port owned by a
// process are client sockets and are left out.
func ListeningPorts(lines []string, ephLo, ephHi int) []string {
	var out []string
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		i := strings.LastIndexByte(f[4], ':')
		if i < 0 {
			continue
		}
		addr := strings.TrimSuffix(strings.TrimPrefix(f[4][:i], "["), "]")
		if j := strings.IndexByte(addr, '%'); j > 0 {
			addr = addr[:j]
		}
		port, err := strconv.Atoi(f[4][i+1:])
		if err != nil || port == 0 || strings.HasPrefix(addr, "127.") || addr == "::1" || strings.HasPrefix(addr, "::ffff:127.") {
			continue
		}
		if f[0] == "udp" && port >= ephLo && port <= ephHi && strings.Contains(l, "users:(") {
			continue
		}
		out = append(out, fmt.Sprintf("%d/%s", port, f[0]))
	}
	return out
}

func sortPorts(ps []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ps {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.Split(out[i], "/")[0])
		b, _ := strconv.Atoi(strings.Split(out[j], "/")[0])
		if a != b {
			return a < b
		}
		return out[i] < out[j]
	})
	return out
}

// forwardingUnused: turning IP forwarding off breaks whatever routes packets.
func forwardingUnused(ctx context.Context, t *target.Target) (bool, string) {
	out, _ := t.Output(ctx, `
systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | awk '{print $1}' |
  grep -E '^(docker|containerd|podman|kubelet|k3s|k3s-agent|rke2-server|rke2-agent|k0s.*|libvirtd|virtqemud|lxc|lxc-net|lxd|snap\.lxd\.daemon|incus|pve-cluster|pve-firewall|tailscaled|zerotier-one|openvpn-server@.*|openvpn@.*|strongswan.*|ipsec|wg-quick@.*|frr|bird|keepalived)\.service$' |
  sed 's/\.service$//'
ip -o link show type bridge 2>/dev/null | awk -F': ' '{print "bridge " $2}' | sed 's/@.*//'
ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print "wireguard " $2}'
iptables -t nat -S POSTROUTING 2>/dev/null | grep -q MASQUERADE && echo "NAT masquerading rules"
nft list ruleset 2>/dev/null | grep -q masquerade && echo "NAT masquerading rules"
true`, true)
	var found []string
	seen := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" && !seen[l] {
			seen[l] = true
			found = append(found, l)
		}
	}
	if len(found) > 0 {
		return false, "this host forwards packets for " + strings.Join(found, ", ") + ": turning forwarding off would cut them. Waive the control instead"
	}
	return true, "no container runtime, VM bridge, VPN or NAT found"
}

// removalContained: removing a package must not take other packages with it
// (apt and dnf remove what depends on it: gcc takes dkms, which builds
// kernel modules).
func removalContained(ctx context.Context, t *target.Target, it Item) (bool, string) {
	var pkgs []string
	for _, a := range it.Actions {
		if a["kind"] != "packages_absent" {
			continue
		}
		if l, ok := a["packages"].([]any); ok {
			for _, x := range l {
				pkgs = append(pkgs, fmt.Sprint(x))
			}
		}
	}
	if len(pkgs) == 0 {
		return true, "nothing to remove"
	}
	quoted := make([]string, len(pkgs))
	for i, p := range pkgs {
		quoted[i] = target.Quote(p)
	}
	list := strings.Join(quoted, " ")
	out, _ := t.Output(ctx, `
set -- `+list+`
inst=""
for p in "$@"; do
  if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${db:Status-Abbrev}' "$p" 2>/dev/null | grep -q '^ii' && inst="$inst $p"
  elif command -v rpm >/dev/null 2>&1; then
    rpm -q "$p" >/dev/null 2>&1 && inst="$inst $p"
  fi
done
[ -n "$inst" ] || exit 0
echo "installed:$inst"
if command -v apt-get >/dev/null 2>&1; then
  apt-get -s -q remove $inst 2>/dev/null | awk '/^Remv /{print "removes:" $2}'
elif command -v dnf >/dev/null 2>&1; then
  dnf -q --assumeno remove $inst 2>&1 | awk '/^Removing dependent packages:/{d=1; next} /^[^ ]/{d=0} d && NF {print "removes:" $1}'
fi
true`, true)
	listed := map[string]bool{}
	for _, p := range pkgs {
		listed[p] = true
	}
	var extra []string
	installed := ""
	for _, l := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), ":")
		switch k {
		case "installed":
			installed = strings.TrimSpace(v)
		case "removes":
			name := strings.SplitN(v, ":", 2)[0] // apt prints pkg:arch for multi-arch
			if !listed[name] {
				extra = append(extra, name)
			}
		}
	}
	if installed == "" {
		return true, "none of the packages is installed"
	}
	if len(extra) > 0 {
		return false, "removing " + installed + " would also remove " + strings.Join(extra, ", ") + ": remove them yourself if you really mean it"
	}
	return true, "removes only " + installed
}
