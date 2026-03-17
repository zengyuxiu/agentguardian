//go:build integration && linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const helperSource = `package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
)

func fail(err error) {
	if os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "ENOENT")
		os.Exit(42)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: helper <path>")
		os.Exit(2)
	}

	runtime.GOMAXPROCS(2)
	runtime.LockOSThread()
	time.Sleep(1500 * time.Millisecond)
	file, err := os.Open(os.Args[1])
	runtime.UnlockOSThread()
	if err != nil {
		fail(err)
	}
	defer file.Close()

	dataCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		data, err := io.ReadAll(file)
		if err != nil {
			errCh <- err
			return
		}
		dataCh <- data
	}()

	select {
	case err := <-errCh:
		fail(err)
	case data := <-dataCh:
		fmt.Print(string(data))
	case <-time.After(5 * time.Second):
		fmt.Fprintln(os.Stderr, "timeout")
		os.Exit(3)
	}
}
`

type privilegeRunner struct {
	useSudo bool
}

type agentProcess struct {
	cmd     *exec.Cmd
	waitCh  chan error
	waitErr error
	priv    privilegeRunner
	pidFile string
	logFile string
}

func TestRewriteExecutableAcrossThreads(t *testing.T) {
	priv := requireBPFPrivileges(t)
	workDir := repoRoot(t)
	agentBin := buildAgentBinary(t, workDir)
	helperBin := buildHelperBinary(t, workDir)

	targetPath := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(targetPath, []byte("secret-token\n"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}

	agent := startAgent(t, workDir, priv, agentBin,
		"-path", targetPath,
		"-rewrite-pid", "0",
		"-rewrite-exe", helperBin,
		"-find", "secret",
		"-replace", "public",
	)
	defer agent.Stop(t)

	output, err := runCommand(workDir, 8*time.Second, helperBin, targetPath)
	if err != nil {
		t.Fatalf("run rewrite helper: %v\noutput:\n%s", err, output)
	}
	if output != "public-token\n" {
		t.Fatalf("unexpected rewritten output: %q", output)
	}

	if err := agent.WaitForLog("op=rewrite action=rewrite", 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestHideExecutable(t *testing.T) {
	priv := requireBPFPrivileges(t)
	workDir := repoRoot(t)
	agentBin := buildAgentBinary(t, workDir)
	helperBin := buildHelperBinary(t, workDir)

	targetPath := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(targetPath, []byte("secret-token\n"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}

	agent := startAgent(t, workDir, priv, agentBin,
		"-path", targetPath,
		"-hide-pid", "0",
		"-hide-exe", helperBin,
		"-find", "secret",
		"-replace", "public",
	)
	defer agent.Stop(t)

	if strings.Contains(agent.Logs(), "hide action disabled") {
		t.Skip("kernel does not support lsm/file_open for hide enforcement")
	}

	output, err := runCommand(workDir, 8*time.Second, helperBin, targetPath)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("hide helper should fail with ENOENT, err=%v output=%q", err, output)
	}
	if exitErr.ExitCode() != 42 {
		t.Fatalf("unexpected hide helper exit code: %d output=%q", exitErr.ExitCode(), output)
	}
	if !strings.Contains(output, "ENOENT") {
		t.Fatalf("hide helper output should contain ENOENT, got %q", output)
	}

	if err := agent.WaitForLog("op=block action=hide", 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestRewriteIgnoresOtherPaths(t *testing.T) {
	priv := requireBPFPrivileges(t)
	workDir := repoRoot(t)
	agentBin := buildAgentBinary(t, workDir)
	helperBin := buildHelperBinary(t, workDir)

	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "target.txt")
	otherPath := filepath.Join(tmpDir, "other.txt")
	if err := os.WriteFile(targetPath, []byte("secret-token\n"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}
	if err := os.WriteFile(otherPath, []byte("secret-token\n"), 0o644); err != nil {
		t.Fatalf("write other file: %v", err)
	}

	agent := startAgent(t, workDir, priv, agentBin,
		"-path", targetPath,
		"-rewrite-pid", "0",
		"-rewrite-exe", helperBin,
		"-find", "secret",
		"-replace", "public",
	)
	defer agent.Stop(t)

	output, err := runCommand(workDir, 8*time.Second, helperBin, otherPath)
	if err != nil {
		t.Fatalf("run helper for non-target path: %v\noutput:\n%s", err, output)
	}
	if output != "secret-token\n" {
		t.Fatalf("non-target path should stay unchanged, got %q", output)
	}
	if strings.Contains(agent.Logs(), otherPath) {
		t.Fatalf("agent should not log non-target path %q\nlogs:\n%s", otherPath, agent.Logs())
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func buildAgentBinary(t *testing.T, workDir string) string {
	t.Helper()

	out := filepath.Join(t.TempDir(), "agentguardian")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, "./cmd/agentguardian")
	cmd.Dir = workDir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build agentguardian: %v\n%s", err, output)
	}
	return out
}

func buildHelperBinary(t *testing.T, workDir string) string {
	t.Helper()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "main.go")
	out := filepath.Join(dir, "helper")
	if err := os.WriteFile(sourcePath, []byte(helperSource), 0o644); err != nil {
		t.Fatalf("write helper source: %v", err)
	}

	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, sourcePath)
	cmd.Dir = workDir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, output)
	}
	return out
}

func requireBPFPrivileges(t *testing.T) privilegeRunner {
	t.Helper()

	if os.Geteuid() == 0 {
		return privilegeRunner{}
	}

	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		t.Skip("integration test requires root or passwordless sudo")
	}

	cmd := exec.Command(sudoPath, "-n", "true")
	if err := cmd.Run(); err != nil {
		t.Skip("integration test requires passwordless sudo")
	}

	return privilegeRunner{useSudo: true}
}

func startAgent(t *testing.T, workDir string, priv privilegeRunner, agentBin string, args ...string) *agentProcess {
	t.Helper()

	dir := t.TempDir()
	logFile := filepath.Join(dir, "agent.log")
	pidFile := filepath.Join(dir, "agent.pid")

	script := `echo $$ > "$1"
log_file="$2"
shift 2
exec "$@" >"$log_file" 2>&1`

	cmdArgs := append([]string{"sh", "-c", script, "sh", pidFile, logFile, agentBin}, args...)
	cmd := priv.command(cmdArgs...)
	cmd.Dir = workDir

	if err := cmd.Start(); err != nil {
		t.Fatalf("start agentguardian: %v", err)
	}

	proc := &agentProcess{
		cmd:     cmd,
		waitCh:  make(chan error, 1),
		priv:    priv,
		pidFile: pidFile,
		logFile: logFile,
	}
	go func() {
		proc.waitCh <- cmd.Wait()
	}()

	if err := proc.WaitForLog("AgentGuardian active:", 10*time.Second); err != nil {
		t.Fatalf("agentguardian did not become ready: %v", err)
	}

	return proc
}

func (p privilegeRunner) command(args ...string) *exec.Cmd {
	if p.useSudo {
		return exec.Command("sudo", append([]string{"-n"}, args...)...)
	}
	return exec.Command(args[0], args[1:]...)
}

func (p privilegeRunner) killSignal(pid int, signal string) error {
	cmd := p.command("kill", signal, strconv.Itoa(pid))
	return cmd.Run()
}

func (a *agentProcess) Stop(t *testing.T) {
	t.Helper()

	a.pollExit()
	if a.waitCh == nil {
		return
	}

	pid, err := a.readPID()
	if err == nil {
		_ = a.priv.killSignal(pid, "-INT")
	}

	select {
	case err := <-a.waitCh:
		a.waitErr = err
		a.waitCh = nil
	case <-time.After(5 * time.Second):
		if err == nil {
			_ = a.priv.killSignal(pid, "-KILL")
		}
		select {
		case waitErr := <-a.waitCh:
			a.waitErr = waitErr
			a.waitCh = nil
		case <-time.After(5 * time.Second):
			t.Fatalf("agentguardian did not exit after shutdown signal\nlogs:\n%s", a.Logs())
		}
	}
}

func (a *agentProcess) WaitForLog(substr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		a.pollExit()
		logs := a.Logs()
		if strings.Contains(logs, substr) {
			return nil
		}
		if a.waitCh == nil {
			return fmt.Errorf("agentguardian exited before log %q appeared: %v\nlogs:\n%s", substr, a.waitErr, logs)
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timed out waiting for log %q\nlogs:\n%s", substr, a.Logs())
}

func (a *agentProcess) Logs() string {
	data, err := os.ReadFile(a.logFile)
	if err != nil {
		return ""
	}
	return string(data)
}

func (a *agentProcess) pollExit() {
	if a.waitCh == nil {
		return
	}

	select {
	case err := <-a.waitCh:
		a.waitErr = err
		a.waitCh = nil
	default:
	}
}

func (a *agentProcess) readPID() (int, error) {
	data, err := os.ReadFile(a.pidFile)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func runCommand(workDir string, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = workDir
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return string(output), fmt.Errorf("command timed out: %w", ctx.Err())
	}
	return string(output), err
}
