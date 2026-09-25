package harden

import (
	"reflect"
	"strings"
	"testing"
)

func TestRootKeyLogin(t *testing.T) {
	admin := account{Name: "alice", UID: 1000, Key: true, Sudo: true, Password: true}
	cases := []struct {
		name string
		f    facts
		ok   bool
	}{
		{"root with a key", facts{Accounts: []account{{Name: "root", Key: true, Password: true}}}, true},
		{"root without a password", facts{Accounts: []account{{Name: "root"}}}, true},
		{"root password only, nobody else", facts{Accounts: []account{{Name: "root", Password: true}}}, false},
		{"root password only, an admin can reach root", facts{Accounts: []account{{Name: "root", Password: true}, admin}}, true},
		{"root password only, logged in as root over SSH", facts{Accounts: []account{{Name: "root", Password: true}, admin}, Session: "root", OverSSH: true}, false},
	}
	for _, c := range cases {
		if ok, d := rootKeyLogin(c.f); ok != c.ok {
			t.Errorf("%s: ok=%v (%s), want %v", c.name, ok, d, c.ok)
		}
	}
}

// The case of a container reached only as root with a key: refusing root
// entirely must be stopped, refusing root passwords must not.
func TestRootOnlyHost(t *testing.T) {
	f := facts{Accounts: []account{{Name: "root", Key: true}}, PermitRoot: "prohibit-password", Session: "root", OverSSH: true}
	if ok, _ := rootKeyLogin(f); !ok {
		t.Error("root_key_login should pass: root keeps its key logins")
	}
	if len(f.admins()) != 0 || !f.rootOverSSH() {
		t.Error("admin_account_ready and ssh_not_root_session should both stop SA-06.21")
	}
	if ok, _ := keyAccess(f, false); !ok {
		t.Error("ssh_key_access should pass: root logs in with a key")
	}
	if ok, _ := keyAccess(f, true); ok {
		t.Error("ssh_key_access should fail when the same plan refuses root: nobody could log in")
	}
}

func TestKeyAccess(t *testing.T) {
	f := facts{Accounts: []account{{Name: "root", Password: true}, {Name: "alice", UID: 1000, Key: true}, {Name: "bob", UID: 1001, Password: true}}, PermitRoot: "prohibit-password"}
	ok, d := keyAccess(f, false)
	if !ok || !strings.Contains(d, "losing SSH access: root, bob") {
		t.Errorf("got %v %q", ok, d)
	}
	f.Session, f.OverSSH = "bob", true
	if ok, _ := keyAccess(f, false); ok {
		t.Error("bob is logged in over SSH without a key: must fail")
	}
}

func TestSuAlternative(t *testing.T) {
	if ok, _ := suAlternative(facts{Accounts: []account{{Name: "root"}}}); !ok {
		t.Error("root only: nobody relies on su")
	}
	if ok, _ := suAlternative(facts{Accounts: []account{{Name: "root"}, {Name: "alice", UID: 1000}}}); ok {
		t.Error("alice has no sudo: su is her only way to root")
	}
	if ok, _ := suAlternative(facts{Accounts: []account{{Name: "alice", UID: 1000}, {Name: "bob", UID: 1001, Sudo: true}}}); !ok {
		t.Error("bob can use sudo")
	}
}

func TestListeningPorts(t *testing.T) {
	lines := []string{
		`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`,
		`tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=2,fd=3))`,
		`tcp LISTEN 0 128 [::]:443 [::]:* users:(("nginx",pid=3,fd=3))`,
		`udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*`,
		`udp UNCONN 0 0 *:58485 *:* users:(("cloudflared",pid=4,fd=9))`,
		`udp UNCONN 0 0 [::1]:323 [::]:* users:(("chronyd",pid=5,fd=6))`,
	}
	got := sortPorts(ListeningPorts(lines, 32768, 60999))
	want := []string{"22/tcp", "443/tcp", "51820/udp"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
