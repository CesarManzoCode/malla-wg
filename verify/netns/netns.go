// Package netns is the harness for tests that need network namespaces,
// without sudo (contract §7): the test binary re-executes itself inside a
// new user, network and mount namespace where it is uid 0, mounts a tmpfs
// on /run and creates the namespaces it needs with `ip netns add`.
//
// The trap of namespaces in Go: a network namespace belongs to a thread,
// not to a process. A socket or a TUN is created in the namespace of the
// thread that creates it and stays there, whichever thread uses it later.
// Goroutines move between threads and a new goroutine does not inherit the
// namespace of the one that started it. So everything that must live in a
// namespace (listening sockets, raw sockets, TUNs) is created inside Do,
// which pins the goroutine to a thread that joined the namespace; once
// created, it can be used from any goroutine.
package netns

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// childEnv marks the re-executed test binary; its value is the test name.
const childEnv = "MALLA_NETNS_CHILD"

func cloneAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		// An unprivileged process may only map its gid with setgroups denied.
		GidMappingsEnableSetgroups: false,
	}
}

// Require skips t with a message that starts with "needs-privilege:" when
// this process cannot create a user and network namespace. Inside the
// re-executed child it returns at once.
func Require(t testing.TB) {
	t.Helper()
	if os.Getenv(childEnv) != "" {
		return
	}
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Fatalf("netns: %v", err)
	}
	probe := exec.Command(truePath)
	probe.SysProcAttr = cloneAttr()
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("needs-privilege: cannot create user and network namespaces: %v %s", err, out)
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Fatalf("netns: iproute2 is required: %v", err)
	}
}

var setupOnce sync.Once
var setupErr error

// setupChild makes the child's mounts private, mounts a tmpfs on /run so
// `ip netns add` can keep its bind mounts in /run/netns, and creates that
// directory.
func setupChild() error {
	setupOnce.Do(func() {
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			setupErr = fmt.Errorf("make / private: %w", err)
			return
		}
		if err := unix.Mount("tmpfs", "/run", "tmpfs", 0, "mode=0755"); err != nil {
			setupErr = fmt.Errorf("mount tmpfs on /run: %w", err)
			return
		}
		setupErr = os.MkdirAll("/run/netns", 0o755)
	})
	return setupErr
}

// Run calls fn inside a new user, network and mount namespace. The parent
// re-executes the test binary restricted to t's test with CLONE_NEWUSER,
// CLONE_NEWNET and CLONE_NEWNS, uid and gid mapped to 0, and fails t if
// the child fails; the child, which runs the same test from the start,
// prepares /run and calls fn. Code before Run therefore runs in both.
func Run(t *testing.T, fn func(t *testing.T)) {
	t.Helper()
	if os.Getenv(childEnv) == t.Name() {
		if err := setupChild(); err != nil {
			t.Fatalf("netns: %v", err)
		}
		fn(t)
		return
	}
	var pattern []string
	for _, part := range strings.Split(t.Name(), "/") {
		pattern = append(pattern, "^"+regexp.QuoteMeta(part)+"$")
	}
	args := []string{"-test.run", strings.Join(pattern, "/"), "-test.v", "-test.count=1"}
	if testing.Short() {
		args = append(args, "-test.short")
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), childEnv+"="+t.Name())
	cmd.SysProcAttr = cloneAttr()
	out, err := cmd.CombinedOutput()
	t.Logf("netns child output:\n%s", out)
	if err != nil {
		t.Fatalf("netns child: %v", err)
	}
	if strings.Contains(string(out), "--- SKIP: "+t.Name()+" ") {
		t.Skip("netns: the child skipped the test")
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()+" ") {
		t.Fatal("netns: the child did not run the test")
	}
}

// Exec runs args inside namespace ns with `ip netns exec` and returns the
// combined output.
func Exec(ns string, args ...string) ([]byte, error) {
	out, err := exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("ip netns exec %s %s: %w: %s", ns, strings.Join(args, " "), err, out)
	}
	return out, nil
}

// MustExec is Exec that fails t on error.
func MustExec(t testing.TB, ns string, args ...string) []byte {
	t.Helper()
	out, err := Exec(ns, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// IP runs `ip args...` in the current namespace and fails t on error.
func IP(t testing.TB, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// Add creates the namespaces with `ip netns add`, brings up their loopback
// and deletes them when t ends.
func Add(t testing.TB, names ...string) {
	t.Helper()
	for _, ns := range names {
		IP(t, "netns", "add", ns)
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
		MustExec(t, ns, "ip", "link", "set", "lo", "up")
	}
}

// Veth joins namespaces nsA and nsB with a veth pair: interface ifA with
// address addrA (prefix notation) in nsA, ifB with addrB in nsB, both up.
// The names go after "name" and "dev", since ip(8) takes a bare name that is
// a prefix of one of its keywords ("br" of "broadcast") as that keyword.
func Veth(t testing.TB, nsA, ifA, addrA, nsB, ifB, addrB string) {
	t.Helper()
	IP(t, "link", "add", "name", ifA, "netns", nsA, "type", "veth", "peer", "name", ifB, "netns", nsB)
	for _, side := range [][3]string{{nsA, ifA, addrA}, {nsB, ifB, addrB}} {
		MustExec(t, side[0], "ip", "addr", "add", side[2], "dev", side[1])
		MustExec(t, side[0], "ip", "link", "set", "dev", side[1], "up")
	}
}

// Do runs fn on a thread that joined namespace ns. The goroutine stays
// locked to that thread and never unlocks it, so the Go runtime discards
// the thread instead of returning it, still in ns, to the pool. Sockets and
// TUNs that fn creates live in ns; goroutines that fn starts do not (see
// the package comment).
func Do(ns string, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		f, err := os.Open("/run/netns/" + ns)
		if err != nil {
			errc <- err
			return
		}
		defer f.Close()
		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			errc <- fmt.Errorf("setns %s: %w", ns, err)
			return
		}
		errc <- fn()
	}()
	return <-errc
}
