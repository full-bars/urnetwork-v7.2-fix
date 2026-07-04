package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	// "net"
	mathrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/term"

	"github.com/docopt/docopt-go"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

const DefaultApiUrl = "https://api.bringyour.com"
const DefaultConnectUrl = "wss://connect.bringyour.com"

const profitIdleLogInterval = 5 * time.Minute

// this value is set via the linker, e.g.
// -ldflags "-X main.Version=$WARP_VERSION-$WARP_VERSION_CODE"
var Version string

var ErrTokenInvalid = errors.New("auth: token is invalid or expired")

func validateJWTExpiry(byJwt string) error {
	expParser := gojwt.NewParser()
	if tok, _, parseErr := expParser.ParseUnverified(byJwt, gojwt.MapClaims{}); parseErr == nil {
		if claims, ok := tok.Claims.(gojwt.MapClaims); ok {
			if exp, ok := claims["exp"].(float64); ok && time.Now().Unix() > int64(exp)+30 {
				return ErrTokenInvalid
			}
		}
	}
	return nil
}

var provideStartTime time.Time

var proxyWarmupDone atomic.Bool

var webhookClient = &http.Client{Timeout: 5 * time.Second}
var containerIDRe = regexp.MustCompile("^[0-9a-f]{12}$")

type ecoState int

const (
	ecoStateNormal ecoState = iota
	ecoStatePressure
	ecoStateCritical
)

var (
	ecoMonitorStarted atomic.Bool
	startEcoMonitor   = func(ctx context.Context) { go runEcoMemoryMonitor(ctx) }
)

func init() {
	// debug.SetGCPercent(10)

	initGlog()

	// initPprof()
}

func initGlog() {
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Set("v", "0")
	// unlike unix, the android/ios standard is for diagnostics to go to stdout
	os.Stderr = os.Stdout
}

func main() {
	usage := fmt.Sprintf(
		`Connect provider.

The default URLs are:
    api_url: %s
    connect_url: %s

Usage:
    provider auth ([<auth_code>] | --user_auth=<user_auth> [--password=<password>]) [-f]
    	[--api_url=<api_url>]
    	[--max-memory=<mem>]
    	[-v...]
    provider provide [--port=<port>]
        [--api_url=<api_url>]
        [--connect_url=<connect_url>]
        [--max-memory=<mem>]
        [-v...]
    provider auth-provide ([<auth_code>] | --user_auth=<user_auth> [--password=<password>]) [-f]
    	[--port=<port>]
        [--api_url=<api_url>]
        [--connect_url=<connect_url>]
        [--max-memory=<mem>]
        [-v...]
    provider proxy auth add [<key>] <proxy_user> <proxy_password> [-f]
    provider proxy auth remove [<key>] [--all]
    provider proxy add [<key_address>...] [--proxy_file=<proxy_file>] [-f]
    provider proxy remove [<key_address>...] [--all]
    
Options:
    -h --help                        Show this help and exit.
    --version                        Show version.
    -v...                            Enable verbose mode. -v implies verbose level 1,
    				                 -vv implies level 2... etc.
    -f                               Force overwrite the JWT token store file or proxy value, if exists.
                                     By default, existing values will not be overwritten.
    --api_url=<api_url>              Specify a custom API URL to use.
    --connect_url=<connect_url>      Specify a custom connect URL to use.
    --user_auth=<user_auth>	         Login with a username.
    --password=<password>            Login with a password. If --user_auth is used, you will be prompted for your
    				                 password anyways, if you don't specify it using this option.
    -p --port=<port>                 Status server port [default: 0].
    --max-memory=<mem>               Set the maximum amount of memory in bytes, or the suffixes b, kib, mib, gib may be used [This is a soft limit].
    <key>                            Authentication key
    <proxy_user>                     SOCKS5 user
    <proxy_password>                 SOCKS5 password
    <key_address>                    SOCKS5 server as host:port, host:port:user:pass, host:port::, or key@host:port
    --proxy_file=<proxy_file>        A path to a file where each line contains on entry as host:port, host:port:user:pass, host:port::, or key@host:port`,
		DefaultApiUrl,
		DefaultConnectUrl,
	)

	opts, err := docopt.ParseArgs(usage, os.Args[1:], RequireVersion())

	if err != nil {
		panic(err)
	}

	if proxy, _ := opts.Bool("proxy"); proxy {
		if auth, _ := opts.Bool("auth"); auth {
			if add, _ := opts.Bool("add"); add {
				proxyAuthAdd(opts)
			} else if remove, _ := opts.Bool("remove"); remove {
				proxyAuthRemove(opts)
			}
		} else if add, _ := opts.Bool("add"); add {
			proxyAdd(opts)
		} else if remove, _ := opts.Bool("remove"); remove {
			proxyRemove(opts)
		}
	} else if auth_, _ := opts.Bool("auth"); auth_ {
		auth(opts)
	} else if provide_, _ := opts.Bool("provide"); provide_ {
		provide(opts)
	} else if authProvide, _ := opts.Bool("auth-provide"); authProvide {
		auth(opts)
		provide(opts)
	}
}

func auth(opts docopt.Opts) {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	urNetworkDir := filepath.Join(home, ".urnetwork")
	jwtPath := filepath.Join(urNetworkDir, "jwt")

	if _, err := os.Stat(jwtPath); !errors.Is(err, os.ErrNotExist) {
		// jwt exists
		if force, _ := opts.Bool("-f"); !force {
			fmt.Printf("%s exists. Overwrite? [yN]\n", jwtPath)

			reader := bufio.NewReader(os.Stdin)
			confirm, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
				return
			}

		}
	}

	apiUrl, err := opts.String("--api_url")
	if err != nil {
		apiUrl = DefaultApiUrl
	}

	maxMemoryHumanReadable, err := opts.String("--max-memory")
	var maxMemory connect.ByteCount
	if err == nil {
		maxMemory, err = connect.ParseByteCount(maxMemoryHumanReadable)
		if err != nil {
			panic(fmt.Errorf("Bad mem argument: %s", maxMemoryHumanReadable))
		}
	}
	if 0 < maxMemory {
		connect.ResizeMessagePools(maxMemory / 8)
		debug.SetMemoryLimit(maxMemory)
	}

	event := connect.NewEventWithContext(context.Background())
	event.SetOnSignals(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(event.Ctx())
	defer cancel()

	clientStrategy := connect.NewClientStrategyWithDefaults(ctx)

	api := connect.NewBringYourApi(ctx, clientStrategy, apiUrl)

	var byJwt string
	if userAuth, err := opts.String("--user_auth"); err == nil {
		// user_auth and password

		var password string
		if password, err = opts.String("--password"); err == nil && password == "" {
			fmt.Print("Enter password: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				panic(err)
			}
			password = string(passwordBytes)
			fmt.Printf("\n")
		}

		// fmt.Printf("userAuth='%s'; password='%s'\n", userAuth, password)

		loginCallback, loginChannel := connect.NewBlockingApiCallback[*connect.AuthLoginWithPasswordResult](ctx)

		loginArgs := &connect.AuthLoginWithPasswordArgs{
			UserAuth: userAuth,
			Password: password,
		}

		api.AuthLoginWithPassword(loginArgs, loginCallback)

		var loginResult connect.ApiCallbackResult[*connect.AuthLoginWithPasswordResult]
		select {
		case <-ctx.Done():
			os.Exit(0)
		case loginResult = <-loginChannel:
		}

		if loginResult.Error != nil {
			panic(loginResult.Error)
		}
		if loginResult.Result.Error != nil {
			panic(fmt.Errorf("%s", loginResult.Result.Error.Message))
		}
		if loginResult.Result.VerificationRequired != nil {
			panic(fmt.Errorf("Verification required for %s. Use the app or web to complete account setup.", loginResult.Result.VerificationRequired.UserAuth))
		}

		byJwt = loginResult.Result.Network.ByJwt
	} else {
		// auth_code
		authCode, _ := opts.String("<auth_code>")
		if authCode == "" {
			fmt.Print("Enter auth code: ")
			authCodeBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				panic(err)
			}
			authCode = strings.TrimSpace(string(authCodeBytes))
			fmt.Printf("\n")
		}

		authCodeLogin := &connect.AuthCodeLoginArgs{
			AuthCode: authCode,
		}

		authCodeLoginCallback, authCodeLoginChannel := connect.NewBlockingApiCallback[*connect.AuthCodeLoginResult](ctx)

		api.AuthCodeLogin(authCodeLogin, authCodeLoginCallback)

		var authCodeLoginResult connect.ApiCallbackResult[*connect.AuthCodeLoginResult]
		select {
		case <-ctx.Done():
			os.Exit(0)
		case authCodeLoginResult = <-authCodeLoginChannel:
		}

		if authCodeLoginResult.Error != nil {
			panic(authCodeLoginResult.Error)
		}
		if authCodeLoginResult.Result.Error != nil {
			panic(fmt.Errorf("%s", authCodeLoginResult.Result.Error.Message))
		}

		byJwt = authCodeLoginResult.Result.ByJwt
	}

	if byJwt != "" {
		if err := os.MkdirAll(urNetworkDir, 0700); err != nil {
			panic(err)
		}
		os.WriteFile(jwtPath, []byte(byJwt), 0700)
		fmt.Printf("Jwt written to %s\n", jwtPath)
	}
}

func runHealthHeartbeat(ctx context.Context, startTime time.Time, profile string) {
	interval := 5 * time.Minute
	if s := os.Getenv("URNETWORK_HEALTH_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d >= time.Minute {
			interval = d
		}
	}
	if profile == "" {
		profile = "default"
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		uptime := time.Since(startTime).Round(time.Second)
		proxies := connect.ActiveProxyConnections()
		fmt.Printf("[health] uptime=%s profile=%s heap=%dMiB sys=%dMiB connections=%d\n",
			uptime, profile, m.HeapAlloc/1024/1024, m.Sys/1024/1024, proxies)
	}
}

func runOutageWatcher(ctx context.Context, nodeName, envWebhookURL string) {
	const pollInterval = 30 * time.Second
	const cooldown = 5 * time.Minute
	const clearConfirm = 2
	const startConfirm = 10 // 10 * 30s = 5 minutes of continuous degradation

	degraded := false
	degradedCount := 0
	clearCount := 0
	var lastStartFire, lastClearFire time.Time

	webhookURL := resolveAlertWebhook(envWebhookURL)
	if webhookURL != "" {
		tlog("[outage] watcher active node=%s webhook=configured\n", nodeName)
	} else {
		tlog("[outage] watcher active node=%s\n", nodeName)
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Re-resolve every tick so writing ~/.urnetwork/alert_webhook can
		// turn outage alerting on, off, or repoint it without a restart —
		// same reasoning as the hub report URL in bandwidth_reporter.go.
		if resolved := resolveAlertWebhook(envWebhookURL); resolved != webhookURL {
			webhookURL = resolved
			if webhookURL != "" {
				tlog("[outage] webhook updated node=%s webhook=configured\n", nodeName)
			} else {
				tlog("[outage] webhook disabled node=%s\n", nodeName)
			}
		}

		if connect.IsBackendDegraded() {
			clearCount = 0
			if !degraded {
				degradedCount++
				if degradedCount >= startConfirm {
					degraded = true
					tlog("[outage] backend degraded — holding existing connections, not accepting new ones\n")
					if webhookURL != "" && time.Since(lastStartFire) >= cooldown {
						lastStartFire = time.Now()
						go fireWebhook(webhookURL, nodeName, "outage_start",
							"Backend unreachable — provider holding existing connections but not accepting new ones.")
					}
				}
			}
		} else {
			degradedCount = 0
			if degraded {
				clearCount++
				if clearCount >= clearConfirm {
					degraded = false
					clearCount = 0
					tlog("[outage] backend recovered\n")
					if webhookURL != "" && time.Since(lastClearFire) >= cooldown {
						lastClearFire = time.Now()
						go fireWebhook(webhookURL, nodeName, "outage_clear", "Backend connectivity restored.")
					}
				}
			}
		}
	}
}

func provide(opts docopt.Opts) {
	provideStartTime = time.Now()
	port, _ := opts.Int("--port")

	apiUrl, err := opts.String("--api_url")
	if err != nil {
		apiUrl = DefaultApiUrl
	}

	connectUrl, err := opts.String("--connect_url")
	if err != nil {
		connectUrl = DefaultConnectUrl
	}

	maxMemoryHumanReadable, err := opts.String("--max-memory")
	var maxMemory connect.ByteCount
	if err == nil {
		maxMemory, err = connect.ParseByteCount(maxMemoryHumanReadable)
		if err != nil {
			panic(fmt.Errorf("Bad mem argument: %s", maxMemoryHumanReadable))
		}
	}
	if 0 < maxMemory {
		connect.ResizeMessagePools(maxMemory / 8)
		debug.SetMemoryLimit(maxMemory)
	}

	applyPoolAutoSize(maxMemory)

	event := connect.NewEventWithContext(context.Background())
	event.SetOnSignals(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(event.Ctx())
	defer cancel()

	go runOutageWatcher(ctx, os.Getenv("URNETWORK_NODE_NAME"), os.Getenv("URNETWORK_ALERT_WEBHOOK"))
	go runHealthHeartbeat(ctx, provideStartTime, os.Getenv("URNETWORK_PROFILE"))
	go runJWTRefresher(ctx, apiUrl)
	go runEarningWindows(ctx)
	go runProfitHeartbeat(ctx)
	go paceMonitor(ctx)

	provideWithProxy := func(proxySettings *connect.ProxySettings) {
		proxyCtx, proxyCancel := context.WithCancel(ctx)
		defer proxyCancel()

		clientStrategySettings := connect.DefaultClientStrategySettings()
		clientStrategySettings.ProxySettings = proxySettings
		clientSettings := connect.DefaultClientSettings()
		// Load previously-persisted long-lived identity material — the
		// Ed25519 client-key seed and the sequence-level TLS server
		// cert + private key. Missing or invalid files are silently
		// ignored; the client will then generate fresh values and we
		// save them back after construction.
		if seed, err := readProviderClientKeySeed(); err == nil && 0 < len(seed) {
			clientSettings.ClientKeySeed = seed
		}
		if certPem, keyPem, err := readProviderTlsCertAndKey(); err == nil && 0 < len(certPem) && 0 < len(keyPem) {
			if clientSettings.EncryptionSettings == nil {
				clientSettings.EncryptionSettings = connect.DefaultEncryptionSettings()
			}
			clientSettings.EncryptionSettings.ProvideTlsCertificatePem = certPem
			clientSettings.EncryptionSettings.ProvideTlsPrivateKeyPem = keyPem
		}
		localUserNatSettings := connect.DefaultLocalUserNatSettings()
		localUserNatSettings.TcpBufferSettings.ConnectSettings = clientStrategySettings.ConnectSettings
		localUserNatSettings.UdpBufferSettings.ConnectSettings = clientStrategySettings.ConnectSettings
		remoteUserNatProviderSettings := connect.DefaultRemoteUserNatProviderSettings()

		clientStrategy := connect.NewClientStrategy(proxyCtx, clientStrategySettings)

		// Plumb the out-of-band peer-client-key fetcher so each
		// per-peer encryption session can cross-check the
		// contract-supplied public client key against the
		// canonical value served by the platform's unauthenticated
		// `/key/<peerId>` API. Today the session only logs on
		// mismatch; the contract value is still trusted, but
		// operators get an early-warning signal for a substitution
		// attack. Skipped if `EncryptionSettings` is nil
		// (encryption disabled).
		if clientSettings.EncryptionSettings != nil && clientSettings.EncryptionSettings.NewPeerClientPublicKeyFetcher == nil {
			clientSettings.EncryptionSettings.NewPeerClientPublicKeyFetcher = func(peerId connect.Id) func(context.Context) ([]byte, error) {
				return func(fetchCtx context.Context) ([]byte, error) {
					r, err := connect.HttpGetWithStrategy(
						fetchCtx,
						clientStrategy,
						fmt.Sprintf("%s/key/%s", apiUrl, peerId),
						"",
						&connect.GetClientKeyResult{},
						connect.NewNoopApiCallback[*connect.GetClientKeyResult](),
					)
					if err != nil {
						return nil, err
					}
					return r.PublicKey, nil
				}
			}
		}

		byClientJwt, clientId, err := func() (string, connect.Id, error) {
			authFailures := 0
			for {
				admitFailureCount := 0
				if proxySettings != nil {
					admitFailureCount = globalProxyFailureHistory.FailureCount(proxySettings.Address)
				}
				release, waitErr := globalProxyAdmissionGate.Admit(proxyCtx, admitFailureCount)
				if waitErr != nil {
					return "", connect.Id{}, waitErr
				}
				byClientJwt, clientId, err := provideAuth(proxyCtx, clientStrategy, apiUrl, opts)
				if proxySettings != nil {
					if err == nil {
						globalProvenProxies.MarkSucceeded(proxySettings.Address)
						globalProxyFailureHistory.Reset(proxySettings.Address)
					}
					globalAuthRateLimiter.ReportResultForProxy(err, globalProvenProxies.HasSucceeded(proxySettings.Address))
				} else {
					globalAuthRateLimiter.ReportResult(err)
				}
				release()
				if err == nil {
					return byClientJwt, clientId, nil
				}
		if proxySettings != nil {
			globalProxyFailureHistory.RecordFailure(proxySettings.Address)
		}
		authFailures++
		if errors.Is(err, ErrTokenInvalid) {
			fmt.Fprintf(os.Stderr, "FATAL [exit 78]: token invalid or expired — exiting so the startup script can refresh it\n")
			os.Exit(78)
		}
		retryDelay := time.Duration(500+mathrand.Intn(10000)) * time.Millisecond
				fmt.Printf("init proxy auth failed. Will retry in %.2fs\n", float64(retryDelay/time.Millisecond)/1000.0)
				select {
				case <-proxyCtx.Done():
				case <-time.After(retryDelay):
				}
			}
		}()
		if err != nil {
			panic(err)
		}

		instanceId := connect.NewId()

		clientOob := connect.NewApiOutOfBandControl(proxyCtx, clientStrategy, byClientJwt, apiUrl)
		connectClient := connect.NewClient(proxyCtx, clientId, clientOob, clientSettings)
		defer connectClient.Close()

		// Persist the live identity material so the next process
		// start loads the same values. On a fresh install both
		// reads above returned empty and the connect.Client just
		// generated; on subsequent starts we're writing back the
		// same bytes (cheap no-op-equivalent).
		if keyManager := connectClient.ClientKeyManager(); keyManager != nil {
			if seed := keyManager.Seed(); 0 < len(seed) {
				if err := writeProviderClientKeySeed(seed); err != nil {
					fmt.Printf("provider client key save failed: %s\n", err)
				}
			}
		}
		if encManager := connectClient.EncryptionSessionManager(); encManager != nil {
			certPem := encManager.ProvideTlsCertificatePem()
			keyPem := encManager.ProvideTlsPrivateKeyPem()
			if 0 < len(certPem) && 0 < len(keyPem) {
				if err := writeProviderTlsCertAndKey(certPem, keyPem); err != nil {
					fmt.Printf("provider tls cert/key save failed: %s\n", err)
				}
			}
		}

		// routeManager := connect.NewRouteManager(connectClient)
		// contractManager := connect.NewContractManagerWithDefaults(connectClient)
		// connectClient.Setup(routeManager, contractManager)
		// go connectClient.Run()

		fmt.Printf("client_id: %s\n", clientId)
		fmt.Printf("instance_id: %s\n", instanceId)

		auth := &connect.ClientAuth{
			ByJwt: byClientJwt,
			// ClientId: clientId,
			InstanceId: instanceId,
			AppVersion: RequireVersion(),
		}
		connect.NewPlatformTransportWithDefaults(proxyCtx, clientStrategy, connectClient.RouteManager(), connectUrl, auth)
		// go platformTransport.Run(connectClient.RouteManager())

		localUserNat := connect.NewLocalUserNat(proxyCtx, clientId.String(), localUserNatSettings)
		defer localUserNat.Close()

		var bw *connect.ProxyBandwidth
		if proxySettings != nil {
			bw = connect.RegisterProxyBandwidth(proxySettings.Index)
		}
		remoteUserNatProvider := connect.NewRemoteUserNatProvider(connectClient, localUserNat, bw, remoteUserNatProviderSettings)
		defer remoteUserNatProvider.Close()

		if proxySettings != nil && bw != nil {
			startProxyBenchmarks(proxyCtx, bw, proxySettings)
		}

		provideModes := map[protocol.ProvideMode]bool{
			protocol.ProvideMode_Public:  true,
			protocol.ProvideMode_Network: true,
		}
		connectClient.ContractManager().SetProvideModes(provideModes)

		select {
		case <-proxyCtx.Done():
		}
	}

	var wg sync.WaitGroup

	if allProxySettings := readProxySettings(); 0 < len(allProxySettings) {
		fmt.Printf("Using %d proxy servers:\n", len(allProxySettings))

		for i, proxySettings := range allProxySettings {
			var user string
			var password string
			if proxySettings.Auth != nil {
				user = proxySettings.Auth.User
				password = proxySettings.Auth.Password
			}
			fmt.Printf("  proxy[%d] %s (%s/%s)\n",
				i,
				proxySettings.Address,
				obfuscateUser(user),
				obfuscatePassword(password),
			)
		}
		for i, proxySettings := range allProxySettings {
			wg.Add(1)
			go connect.HandleError(func() {
				defer wg.Done()

				initialDelay := time.Duration(i) * 100 * time.Millisecond
				select {
				case <-ctx.Done():
				case <-time.After(initialDelay):
				}

				provideWithProxy(proxySettings)
			})
		}
	} else {
		wg.Add(1)
		go connect.HandleError(func() {
			defer wg.Done()
			provideWithProxy(nil)
		})
	}

	if 0 < port {
		fmt.Printf(
			"Provider %s started. Status on *:%d\n",
			RequireVersion(),
			port,
		)
		statusServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: &Status{},
		}
		defer statusServer.Shutdown(ctx)

		go connect.HandleError(func() {
			defer cancel()
			err := statusServer.ListenAndServe()
			if err != nil {
				fmt.Printf("status error: %s\n", err)
			}
		}, cancel)
	} else {
		fmt.Printf(
			"Provider %s started\n",
			RequireVersion(),
		)
	}

	wg.Wait()

	// exit
	os.Exit(0)
}

func backoffPacer(n int, staggerMs int, now time.Time, proxyCtx context.Context) bool {
	if staggerMs <= 0 {
		return true
	}
	jitter := mathrand.Intn(staggerMs + 1)
	if mathrand.Intn(2) == 0 {
		jitter = -jitter
	}
	wait := time.Duration(n)*time.Duration(staggerMs)*time.Millisecond + time.Duration(jitter)*time.Millisecond
	select {
	case <-proxyCtx.Done():
		return false
	case <-time.After(wait):
	}
	return true
}

func applyTurboSettings(clientSettings *connect.ClientSettings, localUserNatSettings *connect.LocalUserNatSettings) {
	profile := os.Getenv("URNETWORK_PROFILE")
	var windowSize uint32
	var queueBytes connect.ByteCount
	switch profile {
	case "turbo-v4":
		windowSize = 4 * 1024 * 1024
		queueBytes = 8 * 1024 * 1024
	case "turbo-v8":
		windowSize = 8 * 1024 * 1024
		queueBytes = 16 * 1024 * 1024
	default:
		return
	}

	localUserNatSettings.TcpBufferSettings.MaxWindowSize = windowSize
	localUserNatSettings.UdpBufferSettings.MaxWindowSize = windowSize
	localUserNatSettings.SequenceBufferSize = 512
	localUserNatSettings.TcpBufferSettings.SequenceBufferSize = 512
	localUserNatSettings.UdpBufferSettings.SequenceBufferSize = 512
	clientSettings.SendBufferSettings.ResendQueueMaxByteCount = queueBytes
	clientSettings.ReceiveBufferSettings.ReceiveQueueMaxByteCount = queueBytes
	clientSettings.SendBufferSettings.SequenceBufferSize = 64
	clientSettings.ReceiveBufferSettings.SequenceBufferSize = 64
	clientSettings.WebRtcSettings.ReceiveBufferSize = connect.ByteCount(windowSize) * 2
	clientSettings.ContractManagerSettings.ContractTransferByteSeqScale = 2
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(200)
	}
}

func applyEcoSettings(maxMemory connect.ByteCount) {
	if os.Getenv("URNETWORK_PROFILE") != "eco" {
		return
	}
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(50)
	}
	if os.Getenv("GOMEMLIMIT") == "" && maxMemory == 0 {
		ramBytes := connect.DetectEffectiveRAMLimitBytes()
		ecoLimit := ramBytes * 75 / 100
		debug.SetMemoryLimit(ecoLimit)
	}
}

func readMemAvailableMiB() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return -1
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					return v / 1024
				}
			}
		}
	}
	return -1
}

func readCgroupAvailableMiB() int64 {
	const oneTiB = int64(1) << 40
	maxData, maxErr := os.ReadFile("/sys/fs/cgroup/memory.max")
	currData, currErr := os.ReadFile("/sys/fs/cgroup/memory.current")
	if maxErr == nil && currErr == nil {
		maxStr := strings.TrimSpace(string(maxData))
		if maxStr != "max" {
			limit, err1 := strconv.ParseInt(maxStr, 10, 64)
			curr, err2 := strconv.ParseInt(strings.TrimSpace(string(currData)), 10, 64)
			if err1 == nil && err2 == nil && limit > 0 && limit < oneTiB {
				if avail := (limit - curr) / 1024 / 1024; avail >= 0 {
					return avail
				}
				return 0
			}
		}
	}
	limitData, limitErr := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")
	usageData, usageErr := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes")
	if limitErr == nil && usageErr == nil {
		limit, err1 := strconv.ParseInt(strings.TrimSpace(string(limitData)), 10, 64)
		usage, err2 := strconv.ParseInt(strings.TrimSpace(string(usageData)), 10, 64)
		if err1 == nil && err2 == nil && limit > 0 && limit < oneTiB {
			if avail := (limit - usage) / 1024 / 1024; avail >= 0 {
				return avail
			}
			return 0
		}
	}
	return -1
}

func runEcoMemoryMonitor(ctx context.Context) {
	const (
		criticalMiB int64 = 150
		pressureMiB int64 = 300
		recoveryMiB int64 = 450
		gcNormal           = 50
		gcPressure         = 25
		gcCritical         = 10
	)
	state := ecoStateNormal
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			avail := readMemAvailableMiB()
			if avail < 0 {
				continue
			}
			if cgroupAvail := readCgroupAvailableMiB(); cgroupAvail >= 0 && cgroupAvail < avail {
				avail = cgroupAvail
			}
			var next ecoState
			switch {
			case avail <= criticalMiB:
				next = ecoStateCritical
			case avail <= pressureMiB:
				next = ecoStatePressure
			case avail >= recoveryMiB:
				next = ecoStateNormal
			default:
				if state == ecoStateCritical {
					runtime.GC()
				}
				continue
			}
			if next == state {
				if state == ecoStateCritical {
					runtime.GC()
				}
				continue
			}
			state = next
			switch state {
			case ecoStateNormal:
				debug.SetGCPercent(gcNormal)
				tlog("[eco] memory pressure eased (available=%dMiB), GOGC=%d\n", avail, gcNormal)
			case ecoStatePressure:
				debug.SetGCPercent(gcPressure)
				tlog("[eco] memory pressure (available=%dMiB, GOGC=%d → %d)\n", avail, gcNormal, gcPressure)
			case ecoStateCritical:
				runtime.GC()
				debug.SetGCPercent(gcCritical)
				tlog("[eco] memory critical (available=%dMiB, GOGC=%d → %d, forcing GC)\n", avail, gcNormal, gcCritical)
			}
		}
	}
}

func startEcoMonitorOnce(ctx context.Context) {
	if ecoMonitorStarted.CompareAndSwap(false, true) {
		startEcoMonitor(ctx)
	}
}

func earningReason(earning bool, proxiesUp int, clients int64, warmup bool) string {
	switch {
	case earning:
		return "-"
	case warmup:
		return "warmup"
	case proxiesUp == 0:
		return "no_proxies"
	case clients == 0:
		return "idle"
	default:
		return "no_traffic"
	}
}

func proxyAuthRetryDelay(err error, attempt int) time.Duration {
	if isRateLimitedError(err) {
		delay := time.Duration(attempt)*5*time.Second + time.Duration(mathrand.Intn(5000))*time.Millisecond
		if delay > 60*time.Second {
			delay = 60 * time.Second
		}
		return delay
	}
	delay := time.Duration(500+mathrand.Intn(3000)) * time.Millisecond
	if attempt > 1 {
		delay += time.Duration(attempt-1) * time.Second
	}
	if delay > 15*time.Second {
		delay = 15 * time.Second
	}
	return delay
}

func classifyAuthFailureCause(err error) string {
	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "proxy unreachable"):
		return "proxy itself is unreachable (dead/offline SOCKS endpoint — not an API issue)"
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled),
		strings.Contains(errMsg, "Timeout"),
		strings.Contains(errMsg, "timeout"),
		strings.Contains(errMsg, "deadline exceeded"),
		strings.Contains(errMsg, "connection refused"),
		strings.Contains(errMsg, "no such host"):
		return "network error reaching API (check connectivity to api.bringyour.com)"
	default:
		return "API rejected token (check JWT validity)"
	}
}

func proxyAuthSlowRetryDelay(slowAttempt int) time.Duration {
	if slowAttempt < 1 {
		slowAttempt = 1
	}
	base := time.Duration(slowAttempt) * 5 * time.Minute
	if base > 15*time.Minute {
		base = 15 * time.Minute
	}
	return base + time.Duration(mathrand.Intn(30000))*time.Millisecond
}

const (
	proxyURLGiveUpRetryBase = 15 * time.Minute
	proxyURLGiveUpRetryCap  = 24 * time.Hour
	proxyURLGiveUpEvictAfterCycles = 10
)

func proxyURLGiveUpRetryDelay(giveUpCount int) time.Duration {
	if giveUpCount < 1 {
		giveUpCount = 1
	}
	delay := proxyURLGiveUpRetryBase
	for i := 1; i < giveUpCount; i++ {
		delay *= 2
		if delay >= proxyURLGiveUpRetryCap {
			delay = proxyURLGiveUpRetryCap
			break
		}
	}
	jitter := time.Duration(mathrand.Int63n(int64(delay)/5 + 1))
	return delay + jitter
}

func readSHMLog(path string, n int) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if n <= 0 {
		return string(b), nil
	}
	s := strings.TrimRight(string(b), "\n")
	lines := strings.Split(s, "\n")
	if n > len(lines) {
		n = len(lines)
	}
	return strings.Join(lines[len(lines)-n:], "\n") + "\n", nil
}

func applyPoolAutoSize(maxMemory connect.ByteCount) {
	if maxMemory > 0 {
		return
	}
	if os.Getenv("URNETWORK_PROFILE") == "lowmem" {
		return
	}
	ram := connect.DetectEffectiveRAMLimitBytes()
	poolBytes := connect.ByteCount(ram) / 32
	const floor = 8 * 1024 * 1024
	const ceiling = 256 * 1024 * 1024
	if poolBytes < floor {
		poolBytes = floor
	}
	if poolBytes > ceiling {
		poolBytes = ceiling
	}
	connect.ResizeMessagePools(poolBytes)
	fmt.Printf("[pool] message pool %dMiB (RAM=%dMiB)\n", poolBytes/1024/1024, connect.ByteCount(ram)/1024/1024)
}

// providerStatePath returns the absolute filesystem path of a named
// provider state file under ~/.urnetwork (alongside `jwt`). Does not
// create the directory.
func providerStatePath(name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".urnetwork", name), nil
}

// readProviderClientKeySeed loads the Ed25519 seed for the provider
// client's long-lived identity key from `~/.urnetwork/.provider.key`.
// Returns (nil, nil) when the file does not exist — a fresh install.
// The file is the raw 32-byte seed; no encoding.
func readProviderClientKeySeed() ([]byte, error) {
	p, err := providerStatePath(".provider.key")
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// writeProviderClientKeySeed persists the Ed25519 seed to
// `~/.urnetwork/.provider.key` with 0600 permissions (sensitive
// material — anyone with this file can impersonate the provider
// against the platform identity layer).
func writeProviderClientKeySeed(seed []byte) error {
	p, err := providerStatePath(".provider.key")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	return os.WriteFile(p, seed, 0600)
}

// readProviderTlsCertAndKey loads the sequence-level TLS server cert
// chain and matching private key from `~/.urnetwork/.provider.cert`
// (PEM, leaf first, possibly chained) and the private key from the
// same file (the PEM blocks are concatenated: cert blocks first,
// then a single `PRIVATE KEY` block). Returns (nil, nil, nil) when
// the file does not exist.
func readProviderTlsCertAndKey() (certPem []byte, keyPem []byte, returnErr error) {
	p, err := providerStatePath(".provider.cert")
	if err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	// Split into cert blocks and the private key block.
	rest := b
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		// re-encode the block so the output is canonical PEM (one
		// trailing newline per block).
		blockPem := pem.EncodeToMemory(block)
		if block.Type == "CERTIFICATE" {
			certPem = append(certPem, blockPem...)
		} else {
			// First non-cert block (typically `PRIVATE KEY` or
			// `EC PRIVATE KEY`) is treated as the key. Stop after
			// the first key block.
			keyPem = blockPem
			break
		}
		rest = next
	}
	return certPem, keyPem, nil
}

// writeProviderTlsCertAndKey persists the sequence-level TLS server
// cert and private key to `~/.urnetwork/.provider.cert` with 0600
// permissions. The cert blocks are written first, then the private
// key block, so the on-disk file is a self-contained PEM bundle.
func writeProviderTlsCertAndKey(certPem, keyPem []byte) error {
	p, err := providerStatePath(".provider.cert")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	out := make([]byte, 0, len(certPem)+len(keyPem))
	out = append(out, certPem...)
	out = append(out, keyPem...)
	return os.WriteFile(p, out, 0600)
}

func provideAuth(ctx context.Context, clientStrategy *connect.ClientStrategy, apiUrl string, opts docopt.Opts) (byClientJwt string, clientId connect.Id, returnErr error) {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	jwtPath := filepath.Join(home, ".urnetwork", "jwt")

	if _, err := os.Stat(jwtPath); errors.Is(err, os.ErrNotExist) {
		// jwt does not exist
		returnErr = fmt.Errorf("Jwt does not exist at %s", jwtPath)
		return
	}

	byJwtBytes, err := os.ReadFile(jwtPath)
	if err != nil {
		returnErr = err
		return
	}
	byJwt := strings.TrimSpace(string(byJwtBytes))

	if err := validateJWTExpiry(byJwt); err != nil {
		returnErr = err
		return
	}

	api := connect.NewBringYourApi(ctx, clientStrategy, apiUrl)

	api.SetByJwt(byJwt)

	authClientCallback, authClientChannel := connect.NewBlockingApiCallback[*connect.AuthNetworkClientResult](ctx)

	authClientArgs := &connect.AuthNetworkClientArgs{
		Description: fmt.Sprintf("provider %s %s", runtime.GOOS, RequireVersion()),
		DeviceSpec:  "",
	}

	api.AuthNetworkClient(authClientArgs, authClientCallback)

	var authClientResult connect.ApiCallbackResult[*connect.AuthNetworkClientResult]
	select {
	case <-ctx.Done():
		os.Exit(0)
	case authClientResult = <-authClientChannel:
	}

	if authClientResult.Error != nil {
		panic(authClientResult.Error)
	}
	if authClientResult.Result.Error != nil {
		panic(fmt.Errorf("%s", authClientResult.Result.Error.Message))
	}

	byClientJwt = authClientResult.Result.ByClientJwt

	// parse the clientId
	parser := gojwt.NewParser()
	token, _, err := parser.ParseUnverified(byClientJwt, gojwt.MapClaims{})
	if err != nil {
		panic(err)
	}

	claims := token.Claims.(gojwt.MapClaims)

	clientId, err = connect.ParseId(claims["client_id"].(string))
	if err != nil {
		panic(err)
	}

	return
}

type Status struct {
}

func (self *Status) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type WarpStatusResult struct {
		Version       string `json:"version,omitempty"`
		ConfigVersion string `json:"config_version,omitempty"`
		Status        string `json:"status"`
		ClientAddress string `json:"client_address,omitempty"`
		Host          string `json:"host"`
	}

	result := &WarpStatusResult{
		Version: RequireVersion(),
		// ConfigVersion: RequireConfigVersion(),
		Status: "ok",
		Host:   RequireHost(),
	}

	responseJson, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(responseJson)
}

func Host() (string, error) {
	host := os.Getenv("WARP_HOST")
	if host != "" {
		return host, nil
	}
	host, err := os.Hostname()
	if err == nil {
		return host, nil
	}
	return "", errors.New("WARP_HOST not set")
}

func RequireHost() string {
	host, err := Host()
	if err != nil {
		panic(err)
	}
	return host
}

func RequireVersion() string {
	if version := os.Getenv("WARP_VERSION"); version != "" {
		return version
	}
	return Version
}

func proxyAuthAdd(opts docopt.Opts) {
	proxyConfig := readProxyConfig()

	key, _ := opts.String("key")
	user, _ := opts.String("proxy_user")
	password, _ := opts.String("proxy_password")

	if proxyConfig.Auths == nil {
		proxyConfig.Auths = map[string]*ProxyAuth{}
	}

	if _, ok := proxyConfig.Auths[key]; ok {
		if force, _ := opts.Bool("-f"); !force {
			fmt.Printf("auth key \"%s\" exists. Overwrite? [yN]\n", key)

			reader := bufio.NewReader(os.Stdin)
			confirm, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
				return
			}
		}
	}

	proxyConfig.Auths[key] = &ProxyAuth{
		User:     user,
		Password: password,
	}

	writeProxyConfig(proxyConfig)
}

func proxyAuthRemove(opts docopt.Opts) {
	proxyConfig := readProxyConfig()

	if all, _ := opts.Bool("--all"); all {
		clear(proxyConfig.Auths)
	} else {

		key, _ := opts.String("key")

		if proxyConfig.Auths == nil {
			proxyConfig.Auths = map[string]*ProxyAuth{}
		}

		delete(proxyConfig.Auths, key)
	}

	writeProxyConfig(proxyConfig)
}

func proxyAdd(opts docopt.Opts) {
	proxyConfig := readProxyConfig()

	allKeyAddress := []string{}
	if allKeyAddressAny, ok := opts["<key_address>"]; ok {
		allKeyAddress = append(allKeyAddress, allKeyAddressAny.([]string)...)
	}
	if proxyPath, _ := opts.String("--proxy_file"); proxyPath != "" {
		b, err := os.ReadFile(proxyPath)
		if err != nil {
			panic(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && line[0] != '#' {
				allKeyAddress = append(allKeyAddress, line)
			}
		}
	}

	if proxyConfig.Servers == nil {
		proxyConfig.Servers = map[string]string{}
	}

	for _, keyAddress := range allKeyAddress {
		var key string
		var proxyAddress string
		i := strings.Index(keyAddress, "@")
		if 0 <= i {
			key = keyAddress[:i]
			proxyAddress = keyAddress[i+1:]
		} else {
			key = ""
			proxyAddress = keyAddress
		}

		address, user, password := parseProxyAddress(proxyAddress)
		if proxyConfig.Auths != nil {
			proxyAuth, ok := proxyConfig.Auths[key]
			if ok {
				user = proxyAuth.User
				password = proxyAuth.Password
			}
		}

		if currentKey, ok := proxyConfig.Servers[proxyAddress]; ok && currentKey != key {
			if force, _ := opts.Bool("-f"); !force {
				fmt.Printf(
					"server %s (%s/%s) exists with different key. Change key? [yN]\n",
					address,
					obfuscateUser(user),
					obfuscatePassword(password),
				)

				reader := bufio.NewReader(os.Stdin)
				confirm, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
					return
				}
			}
		}

		fmt.Printf(
			"added server %s (%s/%s)\n",
			address,
			obfuscateUser(user),
			obfuscatePassword(password),
		)

		proxyConfig.Servers[proxyAddress] = key
	}

	writeProxyConfig(proxyConfig)
}

func proxyRemove(opts docopt.Opts) {
	proxyConfig := readProxyConfig()

	if all, _ := opts.Bool("--all"); all {
		clear(proxyConfig.Servers)
	} else {

		allKeyAddress := []string{}
		if allKeyAddressAny, ok := opts["<key_address>"]; ok {
			allKeyAddress = append(allKeyAddress, allKeyAddressAny.([]string)...)
		}

		if proxyConfig.Servers == nil {
			proxyConfig.Servers = map[string]string{}
		}

		for _, keyAddress := range allKeyAddress {
			var key string
			var address string
			i := strings.Index(keyAddress, "@")
			if 0 <= i {
				key = keyAddress[:i]
				address = keyAddress[i+1:]
			} else {
				key = ""
				address = keyAddress
			}

			if key == "" || proxyConfig.Servers[address] == key {
				delete(proxyConfig.Servers, address)
			}
		}
	}

	writeProxyConfig(proxyConfig)
}

type ProxyConfig struct {
	Auths map[string]*ProxyAuth `json:"auths"`
	// TODO is there a use case for multiple keys to the same address?
	// address -> key
	Servers map[string]string `json:"servers"`
}

type ProxyAuth struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func readProxySettings() []*connect.ProxySettings {
	proxyConfig := readProxyConfig()

	if proxyConfig.Servers == nil {
		return nil
	}

	var allProxySettings []*connect.ProxySettings
	for proxyAddress, key := range proxyConfig.Servers {
		address, user, password := parseProxyAddress(proxyAddress)
		proxySettings := &connect.ProxySettings{
			Network: "tcp",
			Address: address,
		}
		if user != "" || password != "" {
			proxySettings.Auth = &proxy.Auth{
				User:     user,
				Password: password,
			}
		}
		if proxyConfig.Auths != nil {
			proxyAuth, ok := proxyConfig.Auths[key]
			if ok {
				proxySettings.Auth = &proxy.Auth{
					User:     proxyAuth.User,
					Password: proxyAuth.Password,
				}
			}
		}
		allProxySettings = append(allProxySettings, proxySettings)
	}

	return allProxySettings
}

func parseProxyAddress(proxyAddress string) (address string, user string, password string) {
	r := regexp.MustCompile("^(.*:\\d*):([^:]*):([^:]*)$")
	groups := r.FindStringSubmatch(proxyAddress)
	if groups != nil {
		address = groups[1]
		user = groups[2]
		password = groups[3]
		return
	}
	// assume host:port
	address = proxyAddress
	return
}

func obfuscateUser(user string) string {
	if user == "" {
		return "<no user>"
	} else if len(user) < 6 {
		return "***"
	} else {
		return fmt.Sprintf("%s***%s", user[:2], user[len(user)-2:])
	}
}

func obfuscatePassword(password string) string {
	if password == "" {
		return "<no password>"
	} else if len(password) < 6 {
		return "***"
	} else {
		return fmt.Sprintf("%s***%s", password[:2], password[len(password)-2:])
	}
}

func readProxyConfig() *ProxyConfig {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	urNetworkDir := filepath.Join(home, ".urnetwork")
	proxyPath := filepath.Join(urNetworkDir, "proxy")

	if _, err := os.Stat(proxyPath); errors.Is(err, os.ErrNotExist) {
		return &ProxyConfig{}
	}

	b, err := os.ReadFile(proxyPath)
	if err != nil {
		panic(err)
	}

	var proxyConfig ProxyConfig
	err = json.Unmarshal(b, &proxyConfig)
	if err != nil {
		panic(err)
	}
	return &proxyConfig
}

func writeProxyConfig(proxyConfig *ProxyConfig) {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	urNetworkDir := filepath.Join(home, ".urnetwork")
	proxyPath := filepath.Join(urNetworkDir, "proxy")

	if _, err := os.Stat(urNetworkDir); os.IsNotExist(err) {
		err = os.MkdirAll(urNetworkDir, 0700)
		if err != nil {
			panic(err)
		}
	}

	b, err := json.Marshal(proxyConfig)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(proxyPath, b, 0700)
	if err != nil {
		panic(err)
	}

	if reloadPath, err := proxyReloadPath(); err == nil {
		if err := writeReloadTrigger(reloadPath); err != nil {
			tlog("[proxy] warn: reload trigger write failed: %v\n", err)
		}
	}
}

func parseJWTExpiryTime(byJwt string) *time.Time {
	parser := gojwt.NewParser()
	tok, _, err := parser.ParseUnverified(byJwt, gojwt.MapClaims{})
	if err != nil {
		return nil
	}
	claims, ok := tok.Claims.(gojwt.MapClaims)
	if !ok {
		return nil
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil
	}
	t := time.Unix(int64(exp), 0)
	return &t
}

func refreshJWT(ctx context.Context, apiUrl, byJwt string) (string, error) {
	clientStrategy := connect.NewClientStrategyWithDefaults(ctx)
	api := connect.NewBringYourApi(ctx, clientStrategy, apiUrl)
	api.SetByJwt(byJwt)
	callback, channel := connect.NewBlockingApiCallback[*connect.AuthNetworkClientResult](ctx)
	api.AuthNetworkClient(&connect.AuthNetworkClientArgs{
		Description: "jwt-refresh",
		DeviceSpec:  "",
	}, callback)
	var result connect.ApiCallbackResult[*connect.AuthNetworkClientResult]
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result = <-channel:
	}
	if result.Error != nil {
		return "", fmt.Errorf("api error: %w", result.Error)
	}
	if result.Result == nil {
		return "", fmt.Errorf("empty result from auth API")
	}
	if result.Result.Error != nil {
		return "", fmt.Errorf("auth rejected: %s", result.Result.Error.Message)
	}
	if result.Result.ByClientJwt == "" {
		return "", fmt.Errorf("empty ByClientJwt in response")
	}
	return result.Result.ByClientJwt, nil
}

func runJWTRefresher(ctx context.Context, apiUrl string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	jwtPath := filepath.Join(home, ".urnetwork", "jwt")
	lastRefreshPath := filepath.Join(home, ".urnetwork", "jwt_last_refresh")
	const periodicInterval = 7 * 24 * time.Hour
	const expiryFallbackWindow = 48 * time.Hour
	jitterMs := time.Duration(mathrand.Intn(10)) * time.Minute
	select {
	case <-time.After(jitterMs):
	case <-ctx.Done():
		return
	}
	readLastRefreshTime := func() time.Time {
		data, err := os.ReadFile(lastRefreshPath)
		if err != nil {
			return time.Time{}
		}
		unixSec, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			return time.Time{}
		}
		return time.Unix(unixSec, 0)
	}
	writeLastRefreshTime := func(t time.Time) error {
		return os.WriteFile(lastRefreshPath, []byte(strconv.FormatInt(t.Unix(), 10)), 0700)
	}
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		byJwtBytes, err := os.ReadFile(jwtPath)
		if err == nil {
			byJwt := strings.TrimSpace(string(byJwtBytes))
			lastRefreshTime := readLastRefreshTime()
			sinceLastRefresh := time.Since(lastRefreshTime)
			periodicDue := sinceLastRefresh >= periodicInterval
			exp := parseJWTExpiryTime(byJwt)
			expiryDue := exp != nil && time.Until(*exp) <= expiryFallbackWindow
			if periodicDue || expiryDue {
				var reason string
				switch {
				case periodicDue && expiryDue:
					reason = fmt.Sprintf("7-day periodic refresh due (last refresh %s ago) and within %s of expiry",
						formatDuration(sinceLastRefresh), formatDuration(expiryFallbackWindow))
				case periodicDue:
					reason = fmt.Sprintf("7-day periodic refresh due (last refresh %s ago)", formatDuration(sinceLastRefresh))
				default:
					reason = fmt.Sprintf("expiry fallback triggered (expires in %s, within %s threshold)",
						formatDuration(time.Until(*exp)), formatDuration(expiryFallbackWindow))
				}
				tlog("[jwt] refreshing token — %s\n", reason)
				newJwt, err := refreshJWT(ctx, apiUrl, byJwt)
				if err != nil {
					tlog("[jwt] refresh failed: %v (will retry in 1h)\n", err)
				} else if err := os.WriteFile(jwtPath, []byte(newJwt), 0700); err != nil {
					tlog("[jwt] failed to write refreshed token: %v (will retry in 1h)\n", err)
				} else {
					now := time.Now()
					if err := writeLastRefreshTime(now); err != nil {
						tlog("[jwt] token refreshed but failed to persist last-refresh timestamp: %v\n", err)
					} else {
						tlog("[jwt] token refreshed successfully (next periodic refresh in %s)\n", formatDuration(periodicInterval))
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dh %dm", h, m)
}

func metricBytesToMiB(name string, v metrics.Value) uint64 {
	switch v.Kind() {
	case metrics.KindUint64:
		return v.Uint64() / 1024 / 1024
	case metrics.KindFloat64:
		return uint64(v.Float64()) / 1024 / 1024
	default:
		return 0
	}
}

func readProxySettingsFromFile(path string) ([]*connect.ProxySettings, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read proxy file %s: %w", path, err)
	}
	var all []*connect.ProxySettings
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		address, user, password := parseProxyAddress(line)
		if user == "" || password == "" {
			tlog("[proxy] error: proxy %q missing credentials\n", line)
			continue
		}
		all = append(all, &connect.ProxySettings{
			Network: "tcp",
			Address: address,
			Auth:    &proxy.Auth{User: user, Password: password},
		})
	}
	return all, nil
}

func removeAddressesFromFile(path string, addresses []string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	removeSet := map[string]bool{}
	for _, a := range addresses {
		removeSet[a] = true
	}
	var kept []string
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		addr, _, _ := parseProxyAddress(trimmed)
		if !removeSet[addr] {
			kept = append(kept, line)
		}
	}
	content := strings.Join(kept, "\n")
	if len(b) > 0 && b[len(b)-1] == '\n' && (len(content) == 0 || content[len(content)-1] != '\n') {
		content += "\n"
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func fmtRate(bytesPerSec float64) string {
	switch {
	case bytesPerSec >= 1e9:
		return fmt.Sprintf("%.1f GB/s", bytesPerSec/1e9)
	case bytesPerSec >= 1e6:
		return fmt.Sprintf("%.1f MB/s", bytesPerSec/1e6)
	case bytesPerSec >= 1e3:
		return fmt.Sprintf("%.1f KB/s", bytesPerSec/1e3)
	default:
		return fmt.Sprintf("%.0f B/s", bytesPerSec)
	}
}

func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func nextMidnight(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, t.Location())
}

func sumLastN(deltas []uint64, n int) uint64 {
	if len(deltas) < n {
		n = len(deltas)
	}
	var total uint64
	for _, d := range deltas[len(deltas)-n:] {
		total += d
	}
	return total
}

func runEarningWindows(ctx context.Context) {
	const maxSamples = 60
	deltas := make([]uint64, 0, maxSamples)
	var prevCum uint64
	var prevSet bool
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if connect.ProxyHealthCount() == 0 {
			prevSet = false
			continue
		}
		_, _, _, bw, _ := connect.ProxyHealthSnapshot()
		var cum uint64
		for _, p := range bw {
			cum += p.BillableRx.Load() + p.BillableTx.Load()
		}
		if prevSet {
			if cum >= prevCum {
				deltas = append(deltas, cum-prevCum)
			} else {
				deltas = append(deltas, 0)
			}
			if len(deltas) > maxSamples {
				deltas = deltas[len(deltas)-maxSamples:]
			}
			billable1m := sumLastN(deltas, 1)
			billable5m := sumLastN(deltas, 5)
			billable15m := sumLastN(deltas, 15)
			billable60m := sumLastN(deltas, 60)
			active := "no"
			if billable1m > 0 {
				active = "yes"
			}
			tlog("💰 [earn] billable_1m=%s billable_5m=%s billable_15m=%s billable_60m=%s active=%s\n",
				fmtBytes(billable1m), fmtBytes(billable5m), fmtBytes(billable15m), fmtBytes(billable60m), active)
		}
		prevCum = cum
		prevSet = true
	}
}

func runProfitHeartbeat(ctx context.Context) {
	const interval = 15 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var prevBillable uint64
	var prevSet bool
	prevTickTime := time.Now()
	var lastLogTime time.Time
	wasEarning := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if connect.ProxyHealthCount() == 0 {
			prevSet = false
			continue
		}
		proxiesUp, _, _, bw, connecting := connect.ProxyHealthSnapshot()
		var billable uint64
		var clients int64
		var serving int
		for _, p := range bw {
			billable += p.BillableRx.Load() + p.BillableTx.Load()
			pc := p.Clients.Load()
			clients += pc
			if pc > 0 {
				serving++
			}
		}
		now := time.Now()
		if !prevSet {
			prevBillable = billable
			prevTickTime = now
			prevSet = true
			continue
		}
		elapsed := now.Sub(prevTickTime).Seconds()
		if elapsed < 1 {
			elapsed = 1
		}
		var delta uint64
		if billable >= prevBillable {
			delta = billable - prevBillable
		}
		prevBillable = billable
		prevTickTime = now
		earning := delta > 0 && clients > 0
		justStopped := wasEarning && !earning
		wasEarning = earning
		if earning || justStopped || lastLogTime.IsZero() || now.Sub(lastLogTime) >= profitIdleLogInterval {
			status := "no"
			if earning {
				status = "yes"
			}
			idle := proxiesUp - serving
			if idle < 0 {
				idle = 0
			}
			warmup := len(connecting) >= 5
			reason := earningReason(earning, proxiesUp, clients, warmup)
			profitEmoji := ""
			if status == "yes" {
				profitEmoji = "💰 "
			}
			tlog("%s[profit] earning=%s reason=%s clients=%d rate=%s proxies_up=%d serving=%d idle=%d\n",
				profitEmoji, status, reason, clients, fmtRate(float64(delta)/elapsed), proxiesUp, serving, idle)
			lastLogTime = now
		}
	}
}

func resolveDuration(opts docopt.Opts, flag, envVar string, def time.Duration) time.Duration {
	if v, _ := opts.String(flag); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		tlog("[proxy][url] warning: invalid duration %q for %s; using default %s\n", v, flag, def)
		return def
	}
	if v := os.Getenv(envVar); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		tlog("[proxy][url] warning: invalid duration %q for %s; using default %s\n", v, envVar, def)
	}
	return def
}

// resolveInt is resolveDuration's integer counterpart.

func resolveInt(opts docopt.Opts, flag, envVar string, def int) int {
	if v, _ := opts.String(flag); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		tlog("[proxy][url] warning: invalid integer %q for %s; using default %d\n", v, flag, def)
		return def
	}
	if v := os.Getenv(envVar); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		tlog("[proxy][url] warning: invalid integer %q for %s; using default %d\n", v, envVar, def)
	}
	return def
}

// resolveString is resolveDuration's plain-string counterpart.

func resolveString(opts docopt.Opts, flag, envVar, def string) string {
	if v, _ := opts.String(flag); v != "" {
		return v
	}
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return def
}

// resolveProxyURLs collects --proxy_url flag values, PROXY_URL env var
// values (comma-separated), and persisted sources from proxy_url.json
// (added via `proxy add-source`), deduplicated, in that priority order.

func resolveProxyURLs(opts docopt.Opts) []string {
	var urls []string

	if v, ok := opts["--proxy_url"]; ok && v != nil {
		switch vv := v.(type) {
		case []string:
			urls = append(urls, vv...)
		case string:
			if vv != "" {
				urls = append(urls, vv)
			}
		}
	}

	if envURLs := os.Getenv("PROXY_URL"); envURLs != "" {
		for _, u := range strings.Split(envURLs, ",") {
			if u = strings.TrimSpace(u); u != "" {
				urls = append(urls, u)
			}
		}
	}

	if urlState, err := readProxyURLState(); err != nil {
		tlog("[proxy][url] warning: could not read proxy_url.json: %v\n", err)
	} else {
		urls = append(urls, urlState.Sources...)
	}

	seen := map[string]bool{}
	deduped := make([]string, 0, len(urls))
	for _, u := range urls {
		if !seen[u] {
			seen[u] = true
			deduped = append(deduped, u)
		}
	}
	return deduped
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		resp := scanner.Text()
		return strings.ToLower(strings.TrimSpace(resp)) == "y"
	}
	return false
}

func applyLowmodeSettings(clientSettings *connect.ClientSettings, localUserNatSettings *connect.LocalUserNatSettings) {
	if os.Getenv("URNETWORK_PROFILE") != "lowmem" {
		return
	}

	// 1. Initial Contract Size: 2 MiB -> 256 KiB
	clientSettings.ContractManagerSettings.InitialContractTransferByteCount = 256 * 1024

	// 2. IP Buffer Depth: 256 -> 16
	localUserNatSettings.SequenceBufferSize = 16
	localUserNatSettings.TcpBufferSettings.SequenceBufferSize = 16
	localUserNatSettings.UdpBufferSettings.SequenceBufferSize = 16

	// 3. TCP Accordion Window: 1MB -> 32KB
	localUserNatSettings.TcpBufferSettings.MaxWindowSize = 32 * 1024
}

// detectEffectiveRAMLimitBytes returns the effective RAM ceiling in bytes.
// Checks cgroup v2, then cgroup v1, then /proc/meminfo MemTotal.
func detectEffectiveRAMLimitBytes() int64 {
	// cgroup v2
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "max" {
			if v, err := strconv.ParseInt(s, 10, 64); err == nil && v > 0 {
				return v
			}
		}
	}
	// cgroup v1 — sentinel for "no limit" is near max int64; filter anything >= 1 TiB
	const oneTiB = 1 << 40
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil && v > 0 && v < oneTiB {
			return v
		}
	}
	// /proc/meminfo MemTotal (kB)
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						return v * 1024
					}
				}
			}
		}
	}
	return 850 * 1024 * 1024
}

func RunStartupAudit() (slowDisk bool, lowSpace bool) {
	tlog("[audit] Running system checks...\n")
	profile := os.Getenv("URNETWORK_PROFILE")
	ramlogs := os.Getenv("URNETWORK_RAMLOGS")

	// If RAM logs are already ON (manually or via profile), skip disk benchmark
	skipDisk := (ramlogs == "1" || profile == "lowmem" || profile == "eco")

	return connect.RunSystemAudit(skipDisk)
}

func fireWebhook(url, nodeName, event, message string) {
	// Format the body per service. Discord requires "content" and Slack requires
	// "text"; a generic {event,node,...} body is rejected by both (HTTP 400). Any
	// other endpoint (ntfy, custom) gets the structured JSON it can parse.
	var payload []byte
	var err error
	switch {
	case strings.Contains(url, "discord.com"), strings.Contains(url, "discordapp.com"):
		line := fmt.Sprintf("URnetwork [%s] node=%s: %s", event, nodeName, message)
		payload, err = json.Marshal(map[string]string{"content": line})
	case strings.Contains(url, "hooks.slack.com"):
		line := fmt.Sprintf("URnetwork [%s] node=%s: %s", event, nodeName, message)
		payload, err = json.Marshal(map[string]string{"text": line})
	default:
		payload, err = json.Marshal(map[string]string{
			"event":     event,
			"node":      nodeName,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"message":   message,
		})
	}
	if err != nil {
		tlog("[webhook] marshal failed: %v\n", err)
		return
	}
	resp, err := webhookClient.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		tlog("[webhook] delivery failed (%s): %v\n", event, err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		tlog("[webhook] non-2xx response (%s): %d\n", event, resp.StatusCode)
	}
}


func paceMonitor(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		up, _, _, _, connecting := connect.ProxyHealthSnapshot()
		total := connect.ProxyHealthCount()
		if total < 5 {
			continue
		}
		pct := float64(up) * 100 / float64(total)
		connectingN := len(connecting)
		elapsed := time.Since(provideStartTime)
		if elapsed > 60*time.Minute {
			tlog("🔥 [pace] warmup: %d/%d up (%.0f%%), %d connecting — forced done after 60m\n",
				up, total, pct, connectingN)
			proxyWarmupDone.Store(true)
			if reloadPath, err := proxyReloadPath(); err == nil {
				if err := writeReloadTrigger(reloadPath); err != nil {
					tlog("[proxy] warn: reload trigger write failed: %v\n", err)
				}
			}
			return
		}
		if pct < 50 && connectingN > 10 {
			tlog("🔥 [pace] ⚠ warmup: %d/%d up (%.0f%%), %d connecting, %d done\n",
				up, total, pct, connectingN, total-up-connectingN)
		} else if pct > 90 && connectingN < 5 {
			tlog("🔥 [pace] ✓ warmup: %d/%d up (%.0f%%), %d connecting — done\n",
				up, total, pct, connectingN)
			proxyWarmupDone.Store(true)
			if reloadPath, err := proxyReloadPath(); err == nil {
				if err := writeReloadTrigger(reloadPath); err != nil {
					tlog("[proxy] warn: reload trigger write failed: %v\n", err)
				}
			}
			return // warmup complete — stop repeating
		} else {
			tlog("🔥 [pace] warmup: %d/%d up (%.0f%%), %d connecting\n",
				up, total, pct, connectingN)
		}
	}
}

