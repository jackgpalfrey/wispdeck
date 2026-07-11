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
		if len(args) < 2 || args[1] != "create" {
			return usageError()
		}
		return createAdmin(args[2:], stdin, stdout)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return nil
	default:
		return usageError()
	}
}

const usage = `Usage:
  wispdeck serve --admin-origin https://admin.example.com [options]
  wispdeck admin create --username USER [options]

Run "wispdeck <command> -h" for command-specific options.
`

func usageError() error { return errors.New(strings.TrimSpace(usage)) }

func serve(args []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	database := flags.String("database", "data/wispdeck.db", "control database path")
	listen := flags.String("listen", "127.0.0.1:8080", "HTTP listen address")
	adminOrigin := flags.String("admin-origin", "", "public admin origin (required)")
	development := flags.Bool("development", false, "allow HTTP and insecure cookies for local development")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("serve does not accept positional arguments")
	}
	if *development && !loopbackAddress(*listen) {
		return errors.New("development mode may listen only on a loopback address")
	}
	origin, err := url.Parse(*adminOrigin)
	if err != nil {
		return fmt.Errorf("parse admin origin: %w", err)
	}
	ctx := context.Background()
	databaseStore, err := store.OpenSQLite(ctx, *database)
	if err != nil {
		return err
	}
	defer databaseStore.Close()
	authService, err := auth.NewService(databaseStore)
	if err != nil {
		return err
	}
	webServer, err := web.New(web.Config{
		AdminOrigin: origin,
		Development: *development,
		Logger:      logger,
	}, authService)
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
	logger.Info("starting Wispdeck admin server", "listen", *listen, "origin", origin.String())
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", err)
	}
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
	usernameFlag := flags.String("username", "", "administrator username")
	passwordStdin := flags.Bool("password-stdin", false, "read password and confirmation as two lines from standard input")
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
	passwordHash, err := auth.HashPassword(password)
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
	_, err = fmt.Fprintf(stdout, "Created administrator %q.\n", username)
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
