package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/branding"
	"github.com/wispdeck/wispdeck/internal/buildinfo"
	"github.com/wispdeck/wispdeck/internal/installation"
	"github.com/wispdeck/wispdeck/internal/shortlink"
	"github.com/wispdeck/wispdeck/internal/site"
	"github.com/wispdeck/wispdeck/internal/store"
	"github.com/wispdeck/wispdeck/internal/updater"
	"github.com/wispdeck/wispdeck/internal/web"
	"github.com/wispdeck/wispdeck/wispist"
	wispistsqlite "github.com/wispdeck/wispdeck/wispist/sqlite"
	"golang.org/x/term"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	err := run(os.Args[1:], os.Stdin, os.Stdout, logger)
	if err != nil {
		if lifecycleErr := handleUpdateLifecycle(err); lifecycleErr == nil {
			return
		} else if !errors.Is(lifecycleErr, err) {
			err = errors.Join(err, lifecycleErr)
		}
		logger.Error("wispdeck failed", "error", err)
		os.Exit(1)
	}
}

type applyUpdateSignal struct {
	request   updater.ApplyRequest
	paths     installation.Paths
	updateDir string
	cause     error
}

func (s *applyUpdateSignal) Error() string { return "restart to apply " + s.request.Release.Version }
func (s *applyUpdateSignal) Unwrap() error { return s.cause }

type rollbackUpdateSignal struct {
	recovery *updater.Recovery
	cause    error
}

func (s *rollbackUpdateSignal) Error() string { return "roll back failed update: " + s.cause.Error() }
func (s *rollbackUpdateSignal) Unwrap() error { return s.cause }

func handleUpdateLifecycle(runErr error) error {
	var apply *applyUpdateSignal
	if errors.As(runErr, &apply) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		recovery, err := updater.Activate(ctx, updater.ActivationConfig{
			Paths: apply.paths, UpdateDir: apply.updateDir,
			Release: apply.request.Release, StagedPath: apply.request.StagedPath,
			Current: buildinfo.Current(),
		})
		if err != nil {
			return fmt.Errorf("activate update: %w", err)
		}
		if err := execWispdeck(recovery.Executable()); err != nil {
			previous, rollbackErr := updater.Rollback(ctx, recovery)
			if rollbackErr != nil {
				return errors.Join(fmt.Errorf("start updated executable: %w", err), rollbackErr)
			}
			return execWispdeck(previous)
		}
		return nil
	}
	var rollback *rollbackUpdateSignal
	if errors.As(runErr, &rollback) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		previous, err := updater.Rollback(ctx, rollback.recovery)
		if err != nil {
			return err
		}
		return execWispdeck(previous)
	}
	return runErr
}

func execWispdeck(executable string) error {
	arguments := append([]string{executable}, os.Args[1:]...)
	return syscall.Exec(executable, arguments, os.Environ())
}

func run(args []string, stdin io.Reader, stdout io.Writer, logger *slog.Logger) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "version":
		return printVersion(args[1:], stdout)
	case "backup":
		if len(args) < 2 {
			return usageError()
		}
		switch args[1] {
		case "create":
			return createBackup(args[2:], stdout)
		case "restore":
			return restoreBackup(args[2:], stdout)
		default:
			return usageError()
		}
	case "serve":
		return serve(args[1:], logger)
	case "doctor":
		return doctor(args[1:], stdout)
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
  wispdeck version [--json]
  wispdeck backup create --output FILE [options]
  wispdeck backup restore --input FILE --yes [options]
  wispdeck serve --app-origin https://wispdeck.example.com [options]
  wispdeck doctor --app-origin https://wispdeck.example.com [options]
  wispdeck admin create --username USER [options]
  wispdeck admin reset-mfa --username USER --yes [options]
  wispdeck admin reset-password --username USER --yes [options]
  wispdeck auth-key generate [options]

Run "wispdeck <command> -h" for command-specific options.
`

func usageError() error { return errors.New(strings.TrimSpace(usage)) }

func printVersion(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	jsonOutput := flags.Bool("json", false, "print machine-readable build metadata")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("version does not accept positional arguments")
	}
	info := buildinfo.Current()
	if *jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(info)
	}
	_, err := fmt.Fprintf(
		stdout, "wispdeck %s (commit %s, built %s, %s)\n",
		info.Version, info.Commit, info.BuiltAt, info.GoVersion,
	)
	return err
}

func createBackup(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("backup create", flag.ContinueOnError)
	output := flags.String("output", "", "new backup archive path (required)")
	database := flags.String("database", "data/wispdeck.db", "control database path")
	wispistData := flags.String("wispist-data", "data/wispist", "Wispist site-data directory")
	authKey := flags.String("auth-key", "data/auth.key", "installation authentication key path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *output == "" {
		return errors.New("backup create requires --output and accepts no positional arguments")
	}
	summary, err := installation.CreateBackup(context.Background(), installation.Paths{
		Database: *database, WispistData: *wispistData, AuthKey: *authKey,
	}, *output, buildinfo.Current().Version)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		stdout, "Created backup %q with %d files (%d bytes).\n",
		*output, summary.Files, summary.Bytes,
	)
	return err
}

func restoreBackup(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("backup restore", flag.ContinueOnError)
	input := flags.String("input", "", "backup archive path (required)")
	database := flags.String("database", "data/wispdeck.db", "control database path")
	wispistData := flags.String("wispist-data", "data/wispist", "Wispist site-data directory")
	authKey := flags.String("auth-key", "data/auth.key", "installation authentication key path")
	confirmed := flags.Bool("yes", false, "confirm replacement of all installation state")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *input == "" || !*confirmed {
		return errors.New("backup restore requires --input, --yes, and no positional arguments")
	}
	summary, err := installation.RestoreBackup(context.Background(), installation.Paths{
		Database: *database, WispistData: *wispistData, AuthKey: *authKey,
	}, *input)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		stdout, "Restored %d files (%d bytes) from %q.\n",
		summary.Files, summary.Bytes, *input,
	)
	return err
}

func serve(args []string, logger *slog.Logger) (result error) {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	embeddedUpdates := buildinfo.Updates()
	database := flags.String("database", "data/wispdeck.db", "control database path")
	wispistData := flags.String("wispist-data", "data/wispist", "Wispist site-data directory")
	authKey := flags.String("auth-key", "data/auth.key", "installation authentication key path")
	listen := flags.String("listen", "127.0.0.1:8080", "HTTP listen address")
	appOrigin := flags.String("app-origin", "", "public application origin (required)")
	siteDomain := flags.String("site-domain", "", "hosted-site domain suffix (defaults to the application hostname)")
	previewDomain := flags.String("preview-domain", "", "isolated preview domain suffix (defaults to preview.<site-domain>)")
	development := flags.Bool("development", false, "allow HTTP and insecure cookies for local development")
	offlinePasswordCheck := flags.Bool("offline-password-check", false, "use only the built-in password blocklist")
	maxLinksPerUser := flags.Int("max-links-per-user", shortlink.DefaultMaxLinksPerUser, "maximum permanently reserved short-link names per user")
	maxSitesPerUser := flags.Int("max-sites-per-user", site.DefaultMaxSitesPerUser, "maximum hosted sites owned by one user")
	maxReleasesPerSite := flags.Int("max-releases-per-site", site.DefaultMaxReleasesPerSite, "maximum retained releases for one hosted site")
	maxSiteStorageMiB := flags.Int64("max-site-storage-mib-per-user", site.DefaultMaxStorageBytesPerUser>>20, "maximum retained hosted-site release storage per user in MiB")
	authEventRetentionDays := flags.Int("auth-event-retention-days", int(store.DefaultAuthEventRetention/(24*time.Hour)), "days to retain authentication audit events")
	maxAuthEvents := flags.Int("max-auth-events", store.DefaultMaxAuthEvents, "maximum retained authentication audit events")
	updateManifestURL := flags.String("update-manifest-url", embeddedUpdates.ManifestURL, "signed stable-release manifest URL")
	updatePublicKey := flags.String("update-public-key", embeddedUpdates.PublicKey, "base64 Ed25519 release-signing public key")
	updatePublicKeyFile := flags.String("update-public-key-file", "", "file containing the base64 release-signing public key")
	updateData := flags.String("update-data", "", "update downloads and pre-update backups directory (defaults beside the control database)")
	retainedUpdateBackups := flags.Int("retained-update-backups", updater.DefaultRetainedBackups, "number of verified pre-update backups to retain")
	retainedUpdateDownloads := flags.Int("retained-update-downloads", updater.DefaultRetainedDownloads, "number of verified update downloads to retain")
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
	if *maxLinksPerUser < 1 {
		return errors.New("max-links-per-user must be at least 1")
	}
	if *maxSitesPerUser < 1 {
		return errors.New("max-sites-per-user must be at least 1")
	}
	if *maxReleasesPerSite < 2 {
		return errors.New("max-releases-per-site must be at least 2")
	}
	if *maxSiteStorageMiB < site.MaxBundleBytes>>20 || *maxSiteStorageMiB > math.MaxInt64>>20 {
		return fmt.Errorf("max-site-storage-mib-per-user must be between %d and %d", site.MaxBundleBytes>>20, int64(math.MaxInt64>>20))
	}
	if *authEventRetentionDays < 1 || *authEventRetentionDays > 3650 {
		return errors.New("auth-event-retention-days must be between 1 and 3650")
	}
	if *maxAuthEvents < 1 || *maxAuthEvents > 10_000_000 {
		return errors.New("max-auth-events must be between 1 and 10000000")
	}
	if *retainedUpdateBackups < 1 || *retainedUpdateBackups > 100 {
		return errors.New("retained-update-backups must be between 1 and 100")
	}
	if *retainedUpdateDownloads < 1 || *retainedUpdateDownloads > 100 {
		return errors.New("retained-update-downloads must be between 1 and 100")
	}
	origin, err := url.Parse(*appOrigin)
	if err != nil {
		return fmt.Errorf("parse application origin: %w", err)
	}
	stateLock, err := installation.AcquireLock(*database)
	if err != nil {
		return fmt.Errorf("start Wispdeck: %w", err)
	}
	defer stateLock.Close()
	generatedAuthKey, err := ensureServeInstallationKey(*database, *authKey)
	if err != nil {
		return err
	}
	if generatedAuthKey {
		logger.Info("generated installation authentication key", "path", *authKey)
	}
	recovery, recoveryErr := updater.BeginStartup(*database, buildinfo.Current().Version, "")
	if recovery != nil {
		defer func() {
			if result != nil && recovery != nil {
				var rollback *rollbackUpdateSignal
				if !errors.As(result, &rollback) {
					result = &rollbackUpdateSignal{recovery: recovery, cause: result}
				}
			}
		}()
	}
	if recoveryErr != nil {
		return recoveryErr
	}
	ctx := context.Background()
	databaseStore, err := store.OpenSQLite(ctx, *database)
	if err != nil {
		return err
	}
	defer databaseStore.Close()
	maintenancePolicy := store.MaintenancePolicy{
		AuthEventRetention: time.Duration(*authEventRetentionDays) * 24 * time.Hour,
		MaxAuthEvents:      *maxAuthEvents,
	}
	if _, err := databaseStore.Maintain(ctx, time.Now().UTC(), maintenancePolicy); err != nil {
		return fmt.Errorf("maintain installation state: %w", err)
	}
	stopMaintenance := startMaintenance(databaseStore, maintenancePolicy, logger)
	defer stopMaintenance()
	brandingFallback := strings.TrimSpace(*siteDomain)
	if brandingFallback == "" {
		brandingFallback = origin.Hostname()
	}
	brandingService, err := branding.NewService(ctx, databaseStore, brandingFallback)
	if err != nil {
		return fmt.Errorf("load instance branding: %w", err)
	}
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
	installationInitialized, err := authService.InstallationInitialized(ctx)
	if err != nil {
		return err
	}
	initialSetupCode := ""
	if !installationInitialized {
		initialSetupCode, err = auth.NewInitialSetupCode()
		if err != nil {
			return err
		}
	}
	passkeyService, err := auth.NewPasskeyService(databaseStore, authService, keyMaterial, origin)
	if err != nil {
		return err
	}
	totpService, err := auth.NewTOTPService(databaseStore, authService, keyMaterial, passkeyService.RPID())
	if err != nil {
		return err
	}
	shortLinkService, err := shortlink.NewService(databaseStore, shortlink.Limits{
		MaxLinksPerUser: *maxLinksPerUser,
	})
	if err != nil {
		return err
	}
	siteService, err := site.NewService(databaseStore, site.Limits{
		MaxSitesPerUser: *maxSitesPerUser, MaxReleasesPerSite: *maxReleasesPerSite,
		MaxStorageBytesPerUser: *maxSiteStorageMiB << 20,
	})
	if err != nil {
		return err
	}
	wispistStores, err := wispistsqlite.NewFactory(*wispistData)
	if err != nil {
		return err
	}
	defer func() {
		if err := wispistStores.Close(); err != nil {
			logger.Error("close Wispist stores", "error", err)
		}
	}()
	wispistEngine, err := wispist.NewEngine(wispist.Config{
		StoreFactory: wispistStores,
		Limits:       wispist.DefaultLimits(),
		RateLimits:   wispist.DefaultRateLimits(),
		Logger:       logger,
	})
	if err != nil {
		return err
	}
	stopVisitFlusher := startVisitFlusher(shortLinkService, logger)
	defer stopVisitFlusher()
	passwordChecker := auth.PasswordChecker(auth.NewStaticPasswordChecker())
	if !*offlinePasswordCheck {
		passwordChecker = auth.NewCombinedPasswordChecker(passwordChecker, auth.NewPwnedPasswordChecker(nil))
	}
	if *updateData == "" {
		*updateData = filepath.Join(filepath.Dir(*database), "updates")
	}
	*updateData, err = updater.ValidateDataDirectory(*updateData, installation.Paths{
		Database: *database, WispistData: *wispistData, AuthKey: *authKey,
	})
	if err != nil {
		return fmt.Errorf("validate update data directory: %w", err)
	}
	artifactRetention := updater.ArtifactRetention{
		Backups: *retainedUpdateBackups, Downloads: *retainedUpdateDownloads,
	}
	if recovery == nil {
		cleanupUpdateArtifacts(*updateData, artifactRetention, logger)
	}
	updateClient, err := configuredUpdateClient(
		*updateManifestURL, *updatePublicKey, *updatePublicKeyFile, *development,
	)
	if err != nil {
		return err
	}
	applyRequests := make(chan updater.ApplyRequest, 1)
	updateManager, err := updater.NewManager(ctx, updater.ManagerConfig{
		Client: updateClient, Repository: databaseStore, Current: buildinfo.Current(),
		StagingDir: filepath.Join(*updateData, "downloads"),
		RequestApply: func(request updater.ApplyRequest) error {
			select {
			case applyRequests <- request:
				return nil
			default:
				return errors.New("an update restart is already pending")
			}
		},
		Logger: logger, InitialDelay: 15 * time.Second,
	})
	if err != nil {
		return err
	}
	webServer, err := web.New(web.Config{
		AppOrigin:         origin,
		SiteDomain:        *siteDomain,
		PreviewDomain:     *previewDomain,
		Development:       *development,
		Logger:            logger,
		PasswordChecker:   passwordChecker,
		TrustedProxyCIDRs: trustedProxies,
		InitialSetupCode:  initialSetupCode,
	}, authService, passkeyService, totpService, shortLinkService, siteService,
		wispistEngine, brandingService, updateManager)
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
	serverContext, cancelServer := context.WithCancel(shutdownContext)
	defer cancelServer()
	type shutdownOutcome struct {
		update *updater.ApplyRequest
	}
	outcomes := make(chan shutdownOutcome, 1)
	go func() {
		var outcome shutdownOutcome
		select {
		case request := <-applyRequests:
			outcome.update = &request
		case <-serverContext.Done():
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
		outcomes <- outcome
	}()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen HTTP: %w", err)
	}
	logger.Info("starting Wispdeck application server", "listen", *listen, "origin", origin.String())
	if !installationInitialized {
		setupURL := *origin
		setupURL.Path = "/onboarding"
		logger.Warn(
			"initial setup required",
			"url", setupURL.String(),
			"setup_code", initialSetupCode,
		)
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- httpServer.Serve(listener) }()
	if recovery != nil {
		if err := probeHealth(serverContext, listener.Addr(), origin.Host); err != nil {
			cancelServer()
			<-outcomes
			<-serveErrors
			return fmt.Errorf("updated server failed its health check: %w", err)
		}
		if err := updater.ConfirmStartup(recovery); err != nil {
			cancelServer()
			<-outcomes
			<-serveErrors
			return fmt.Errorf("confirm updated server startup: %w", err)
		}
		cleanupUpdateArtifacts(*updateData, artifactRetention, logger)
		if err := databaseStore.RecordUpdateEvent(context.Background(), updater.Event{
			OccurredAt: time.Now().UTC(), Kind: "update_succeeded",
			Version: buildinfo.Current().Version,
		}); err != nil {
			logger.Error("record successful update", "error", err)
		}
		recovery = nil
	}
	updateManager.Start(serverContext)
	defer updateManager.Close()
	serveErr := <-serveErrors
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		cancelServer()
		return fmt.Errorf("serve HTTP: %w", serveErr)
	}
	outcome := <-outcomes
	if outcome.update != nil {
		return &applyUpdateSignal{
			request: *outcome.update,
			paths: installation.Paths{
				Database: *database, WispistData: *wispistData, AuthKey: *authKey,
			},
			updateDir: *updateData,
		}
	}
	return nil
}

func configuredUpdateClient(
	manifestURL, encodedPublicKey, publicKeyFile string,
	allowHTTP bool,
) (updater.ReleaseClient, error) {
	return configuredUpdateClientFor(
		buildinfo.Current(), manifestURL, encodedPublicKey, publicKeyFile, allowHTTP,
	)
}

func configuredUpdateClientFor(
	current buildinfo.Info,
	manifestURL, encodedPublicKey, publicKeyFile string,
	allowHTTP bool,
) (updater.ReleaseClient, error) {
	if publicKeyFile != "" {
		info, err := os.Lstat(publicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("inspect update public key file: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 4096 {
			return nil, errors.New("update public key file must be a small regular file")
		}
		body, err := os.ReadFile(publicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read update public key file: %w", err)
		}
		encodedPublicKey = string(body)
	}
	manifestURL = strings.TrimSpace(manifestURL)
	encodedPublicKey = strings.TrimSpace(encodedPublicKey)
	if manifestURL == "" && encodedPublicKey == "" {
		return nil, nil
	}
	if manifestURL == "" || encodedPublicKey == "" {
		return nil, errors.New("update manifest URL and public key must be configured together")
	}
	publicKey, err := updater.ParsePublicKey(encodedPublicKey)
	if err != nil {
		return nil, err
	}
	client, err := updater.NewClient(updater.ClientConfig{
		ManifestURL: manifestURL, PublicKey: publicKey,
		Current: current, AllowHTTP: allowHTTP,
	})
	if err != nil {
		return nil, fmt.Errorf("configure release updates: %w", err)
	}
	return client, nil
}

func probeHealth(ctx context.Context, address net.Addr, applicationHost string) error {
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok {
		return errors.New("HTTP listener does not have a TCP address")
	}
	host := tcpAddress.IP
	if host == nil || host.IsUnspecified() {
		host = net.IPv4(127, 0, 0, 1)
		if tcpAddress.IP != nil && tcpAddress.IP.To4() == nil {
			host = net.IPv6loopback
		}
	}
	target := "http://" + net.JoinHostPort(host.String(), fmt.Sprintf("%d", tcpAddress.Port)) + "/healthz"
	probeContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: time.Second}).DialContext,
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("health check must not redirect")
		},
	}
	var lastErr error
	for {
		request, err := http.NewRequestWithContext(probeContext, http.MethodGet, target, nil)
		if err != nil {
			return err
		}
		request.Host = applicationHost
		response, err := client.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 16))
			closeErr := response.Body.Close()
			if response.StatusCode == http.StatusOK && string(body) == "ok\n" && readErr == nil && closeErr == nil {
				return nil
			}
			err = fmt.Errorf("health response was HTTP %d with body %q", response.StatusCode, body)
		}
		lastErr = err
		select {
		case <-probeContext.Done():
			return errors.Join(lastErr, probeContext.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func startVisitFlusher(service *shortlink.Service, logger *slog.Logger) func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := service.FlushVisits(flushCtx)
				flushCancel()
				if err != nil {
					logger.Error("flush short-link visits", "error", err)
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer flushCancel()
		if err := service.FlushVisits(flushCtx); err != nil {
			logger.Error("final short-link visit flush", "error", err)
		}
	}
}

func startMaintenance(
	database *store.SQLite,
	policy store.MaintenancePolicy,
	logger *slog.Logger,
) func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				maintenanceCtx, maintenanceCancel := context.WithTimeout(ctx, time.Minute)
				summary, err := database.Maintain(maintenanceCtx, now.UTC(), policy)
				maintenanceCancel()
				if err != nil && !errors.Is(err, context.Canceled) {
					logger.Error("maintain installation state", "error", err)
				} else if summary.Removed() > 0 {
					logger.Info("pruned expired installation state", "records", summary.Removed())
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func cleanupUpdateArtifacts(
	directory string,
	retention updater.ArtifactRetention,
	logger *slog.Logger,
) {
	summary, err := updater.CleanupArtifacts(directory, retention)
	if err != nil {
		logger.Error("prune update artifacts", "error", err)
		return
	}
	if summary.Removed() > 0 {
		logger.Info(
			"pruned update artifacts",
			"backups", summary.Backups,
			"downloads", summary.Downloads,
			"temporary", summary.Temporary,
		)
	}
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

func ensureServeInstallationKey(databasePath, keyPath string) (bool, error) {
	if _, err := os.Lstat(databasePath); err == nil {
		if _, keyErr := os.Lstat(keyPath); errors.Is(keyErr, os.ErrNotExist) {
			return false, errors.New("installation authentication key is missing for an existing database; restore the original key or a complete backup")
		} else if keyErr != nil {
			return false, fmt.Errorf("inspect installation authentication key: %w", keyErr)
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect control database: %w", err)
	}
	if _, err := os.Lstat(keyPath); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect installation authentication key: %w", err)
	}
	if err := auth.GenerateInstallationKey(keyPath); err != nil {
		return false, err
	}
	return true, nil
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
	stateLock, err := installation.AcquireLock(*database)
	if err != nil {
		return fmt.Errorf("create administrator: %w", err)
	}
	defer stateLock.Close()
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
	stateLock, err := installation.AcquireLock(*database)
	if err != nil {
		return fmt.Errorf("reset MFA: %w", err)
	}
	defer stateLock.Close()
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
	stateLock, err := installation.AcquireLock(*database)
	if err != nil {
		return fmt.Errorf("reset password: %w", err)
	}
	defer stateLock.Close()
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
