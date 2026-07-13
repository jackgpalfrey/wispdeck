package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/shortlink"
	"github.com/wispdeck/wispdeck/internal/store"
	"github.com/wispdeck/wispdeck/internal/web"
	"golang.org/x/term"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(os.Args[1:], os.Stdin, os.Stdout, logger); err != nil {
		logger.Error("wispdeck failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer, logger *slog.Logger) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], logger)
	case "admin":
		if len(args) < 2 {
			return usageError()
		}
		switch args[1] {
		case "create":
			return createAdmin(args[2:], stdin, stdout)
		case "reset-mfa":
			return resetMFA(args[2:], stdout)
		case "reset-password":
			return resetPassword(args[2:], stdin, stdout)
		default:
			return usageError()
		}
	case "auth-key":
		if len(args) < 2 || args[1] != "generate" {
			return usageError()
		}
		return generateAuthKey(args[2:], stdout)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return nil
	default:
		return usageError()
	}
}

const usage = `Usage:
  wispdeck serve --app-origin https://wispdeck.example.com [options]
  wispdeck admin create --username USER [options]
  wispdeck admin reset-mfa --username USER --yes [options]
  wispdeck admin reset-password --username USER --yes [options]
  wispdeck auth-key generate [options]

Run "wispdeck <command> -h" for command-specific options.
`

func usageError() error { return errors.New(strings.TrimSpace(usage)) }

func serve(args []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	database := flags.String("database", "data/wispdeck.db", "control database path")
	authKey := flags.String("auth-key", "data/auth.key", "installation authentication key path")
	listen := flags.String("listen", "127.0.0.1:8080", "HTTP listen address")
	appOrigin := flags.String("app-origin", "", "public application origin (required)")
	development := flags.Bool("development", false, "allow HTTP and insecure cookies for local development")
	offlinePasswordCheck := flags.Bool("offline-password-check", false, "use only the built-in password blocklist")
	var trustedProxies stringListFlag
	flags.Var(&trustedProxies, "trusted-proxy", "trusted reverse-proxy CIDR (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("serve does not accept positional arguments")
	}
	if *development && !loopbackAddress(*listen) {
		return errors.New("development mode may listen only on a loopback address")
	}
	if *appOrigin == "" {
		return errors.New("serve requires --app-origin")
	}
	origin, err := url.Parse(*appOrigin)
	if err != nil {
		return fmt.Errorf("parse application origin: %w", err)
	}
	ctx := context.Background()
	databaseStore, err := store.OpenSQLite(ctx, *database)
	if err != nil {
		return err
	}
	defer databaseStore.Close()
	keyMaterial, err := auth.LoadInstallationKey(*authKey)
	if err != nil {
		return err
	}
	passwordManager, err := auth.NewPasswordManager(keyMaterial)
	if err != nil {
		return err
	}
	authService, err := auth.NewService(databaseStore, passwordManager)
	if err != nil {
		return err
	}
	passkeyService, err := auth.NewPasskeyService(databaseStore, authService, keyMaterial, origin)
	if err != nil {
		return err
	}
	totpService, err := auth.NewTOTPService(databaseStore, authService, keyMaterial, passkeyService.RPID())
	if err != nil {
		return err
	}
	shortLinkService, err := shortlink.NewService(databaseStore)
	if err != nil {
		return err
	}
	passwordChecker := auth.PasswordChecker(auth.NewStaticPasswordChecker())
	if !*offlinePasswordCheck {
		passwordChecker = auth.NewCombinedPasswordChecker(passwordChecker, auth.NewPwnedPasswordChecker(nil))
	}
	webServer, err := web.New(web.Config{
		AppOrigin:         origin,
		Development:       *development,
		Logger:            logger,
		PasswordChecker:   passwordChecker,
		TrustedProxyCIDRs: trustedProxies,
	}, authService, passkeyService, totpService, shortLinkService)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           webServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}

	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
	}()
	logger.Info("starting Wispdeck application server", "listen", *listen, "origin", origin.String())
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", err)
	}
	return nil
}

type stringListFlag []string

func (values *stringListFlag) String() string { return strings.Join(*values, ",") }

func (values *stringListFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func loopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func createAdmin(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("admin create", flag.ContinueOnError)
	database := flags.String("database", "data/wispdeck.db", "control database path")
	authKey := flags.String("auth-key", "data/auth.key", "installation authentication key path")
	usernameFlag := flags.String("username", "", "superuser username")
	passwordStdin := flags.Bool("password-stdin", false, "read password and confirmation as two lines from standard input")
	skipCompromisedCheck := flags.Bool("skip-compromised-password-check", false, "use only the built-in offline password blocklist")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("admin create does not accept positional arguments")
	}
	username := auth.NormalizeUsername(*usernameFlag)
	if err := auth.ValidateUsername(username); err != nil {
		return err
	}
	password, confirmation, err := readPasswords(stdin, stdout, *passwordStdin)
	if err != nil {
		return err
	}
	if password != confirmation {
		return errors.New("passwords do not match")
	}
	checker := auth.PasswordChecker(auth.NewStaticPasswordChecker())
	if !*skipCompromisedCheck {
		checker = auth.NewCombinedPasswordChecker(checker, auth.NewPwnedPasswordChecker(nil))
	}
	if err := checker.Check(context.Background(), password, auth.PasswordContext{
		Username: username, Service: "wispdeck",
	}); err != nil {
		return err
	}
	keyMaterial, err := auth.LoadInstallationKey(*authKey)
	if err != nil {
		return err
	}
	passwordManager, err := auth.NewPasswordManager(keyMaterial)
	if err != nil {
		return err
	}
	passwordHash, err := passwordManager.Hash(password)
	if err != nil {
		return err
	}
	ctx := context.Background()
	databaseStore, err := store.OpenSQLite(ctx, *database)
	if err != nil {
		return err
	}
	defer databaseStore.Close()
	if _, err := databaseStore.CreateUser(ctx, username, passwordHash, time.Now().UTC()); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Created superuser %q.\n", username)
	return err
}

func generateAuthKey(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("auth-key generate", flag.ContinueOnError)
	path := flags.String("path", "data/auth.key", "installation authentication key path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("auth-key generate does not accept positional arguments")
	}
	if err := auth.GenerateInstallationKey(*path); err != nil {
		return err
	}
	_, err := fmt.Fprintf(stdout, "Created authentication key %q. Back it up securely.\n", *path)
	return err
}

func resetMFA(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("admin reset-mfa", flag.ContinueOnError)
	database := flags.String("database", "data/wispdeck.db", "control database path")
	usernameFlag := flags.String("username", "", "user username")
	confirmed := flags.Bool("yes", false, "confirm destructive local recovery")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !*confirmed {
		return errors.New("reset-mfa requires --username and --yes")
	}
	username := auth.NormalizeUsername(*usernameFlag)
	ctx := context.Background()
	databaseStore, err := store.OpenSQLite(ctx, *database)
	if err != nil {
		return err
	}
	defer databaseStore.Close()
	user, err := databaseStore.UserByUsername(ctx, username)
	if err != nil {
		return err
	}
	if err := databaseStore.ResetUserMFA(ctx, user.ID); err != nil {
		return err
	}
	if err := databaseStore.RecordAuthEvent(ctx, auth.AuthEvent{
		OccurredAt: time.Now().UTC(), Kind: "local_mfa_reset", Username: user.Username, UserID: user.ID,
	}); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Reset MFA for %q and revoked every session.\n", username)
	return err
}

func resetPassword(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("admin reset-password", flag.ContinueOnError)
	database := flags.String("database", "data/wispdeck.db", "control database path")
	authKey := flags.String("auth-key", "data/auth.key", "installation authentication key path")
	usernameFlag := flags.String("username", "", "user username")
	passwordStdin := flags.Bool("password-stdin", false, "read password and confirmation as two lines from standard input")
	skipCompromisedCheck := flags.Bool("skip-compromised-password-check", false, "use only the built-in offline password blocklist")
	confirmed := flags.Bool("yes", false, "confirm destructive local recovery")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !*confirmed {
		return errors.New("reset-password requires --username and --yes")
	}
	username := auth.NormalizeUsername(*usernameFlag)
	if err := auth.ValidateUsername(username); err != nil {
		return err
	}
	password, confirmation, err := readPasswords(stdin, stdout, *passwordStdin)
	if err != nil {
		return err
	}
	if password != confirmation {
		return errors.New("passwords do not match")
	}
	checker := auth.PasswordChecker(auth.NewStaticPasswordChecker())
	if !*skipCompromisedCheck {
		checker = auth.NewCombinedPasswordChecker(checker, auth.NewPwnedPasswordChecker(nil))
	}
	if err := checker.Check(context.Background(), password, auth.PasswordContext{Username: username, Service: "wispdeck"}); err != nil {
		return err
	}
	keyMaterial, err := auth.LoadInstallationKey(*authKey)
	if err != nil {
		return err
	}
	passwordManager, err := auth.NewPasswordManager(keyMaterial)
	if err != nil {
		return err
	}
	hash, err := passwordManager.Hash(password)
	if err != nil {
		return err
	}
	ctx := context.Background()
	databaseStore, err := store.OpenSQLite(ctx, *database)
	if err != nil {
		return err
	}
	defer databaseStore.Close()
	user, err := databaseStore.UserByUsername(ctx, username)
	if err != nil {
		return err
	}
	if err := databaseStore.ResetUserAuthentication(ctx, user.ID, hash, time.Now().UTC()); err != nil {
		return err
	}
	if err := databaseStore.RecordAuthEvent(ctx, auth.AuthEvent{
		OccurredAt: time.Now().UTC(), Kind: "local_password_reset", Username: user.Username, UserID: user.ID,
	}); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Reset password and MFA for %q; every session was revoked.\n", username)
	return err
}

func readPasswords(stdin io.Reader, stdout io.Writer, fromStdin bool) (string, string, error) {
	if fromStdin {
		scanner := bufio.NewScanner(io.LimitReader(stdin, 8<<10))
		if !scanner.Scan() {
			return "", "", errors.New("read password from standard input")
		}
		password := scanner.Text()
		if !scanner.Scan() {
			return "", "", errors.New("read password confirmation from standard input")
		}
		confirmation := scanner.Text()
		if scanner.Scan() {
			return "", "", errors.New("unexpected third line on password input")
		}
		if err := scanner.Err(); err != nil {
			return "", "", fmt.Errorf("read password input: %w", err)
		}
		return password, confirmation, nil
	}
	file, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return "", "", errors.New("standard input is not a terminal; use --password-stdin explicitly")
	}
	_, _ = fmt.Fprint(stdout, "Password: ")
	password, err := term.ReadPassword(int(file.Fd()))
	_, _ = fmt.Fprintln(stdout)
	if err != nil {
		return "", "", fmt.Errorf("read password: %w", err)
	}
	_, _ = fmt.Fprint(stdout, "Confirm password: ")
	confirmation, err := term.ReadPassword(int(file.Fd()))
	_, _ = fmt.Fprintln(stdout)
	if err != nil {
		return "", "", fmt.Errorf("read password confirmation: %w", err)
	}
	return string(password), string(confirmation), nil
}
