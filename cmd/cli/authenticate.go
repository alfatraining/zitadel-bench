package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/alfatraining/zitadel-bench/cmd/cli/pflagutil"
	"github.com/alfatraining/zitadel-bench/internal/zitadel"
	"github.com/prometheus/client_golang/prometheus"
	promsdk "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

type authenticateConfig struct {
	*zitadel.AuthRequest

	metricsURI string
	metrics    metrics
}

func authenticateCmd(zitadelAddress *string, helpEnv *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authenticate",
		Short: "Perform a user authentication against a ZITADEL instance",
		Long: `Perform a user authentication by username and password.

Users of this command have to additionally specify the ID and access token of a
machine user that has the IAM_OWNER role or is a member of the organization the
authenticating user belongs to, the client ID and private key of the application
used for login and the redirect URI that is configured for this application.

Via the --count argument, the authentication can be repeated an arbitrary number
of times (or until the process is killed if 0 is passed).'`,
	}

	conf := authenticateConfig{AuthRequest: &zitadel.AuthRequest{
		Address: *zitadelAddress,
	}}
	cmd.Flags().StringVar(&conf.AuthRequest.MachineAccessToken, "machine-access-token", "", "Access token of a machine user having the required permissions to authenticate users")
	cmd.Flags().StringVar(&conf.AuthRequest.MachineUserID, "machine-user-id", "", "User ID of the machine user")
	cmd.Flags().StringVar(&conf.AuthRequest.ClientID, "client-id", "", "ClientID of the login application")
	cmd.Flags().StringVar(&conf.PrivateKey, "private-key", "", "Private key of the login application")
	cmd.Flags().StringVar(&conf.AuthRequest.RedirectURI, "redirect-uri", "", "Redirect URI configured for the login application (including scheme)")
	cmd.Flags().StringVar(&conf.metricsURI, "metrics-uri", "", "Expose prometheus metrics on this URL. Implies count=0.")
	cmd.Flags().StringVar(&conf.AuthRequest.Username, "username", "", "Username (email address) of the user to authenticate")
	cmd.Flags().StringVar(&conf.AuthRequest.Password, "password", "", "Password of the user to authenticate")
	cmd.Flags().IntVar(&conf.AuthRequest.Count, "count", 1, "Number of authentication retries; setting this value to 0 will let the command retry to authenticate until it is interrupted.")
	cmd.Flags().IntVar(&conf.AuthRequest.Concurrency, "concurrency", 1, "How many simultaneous clients should do an authenticate call. Total number of requests will be 'count*concurrency'.")
	if err := pflagutil.PopulateFromEnv(cmd.Flags()); err != nil {
		log.Fatal("populating config from env:", err)
	}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if *helpEnv {
			pflagutil.PrintEnvUsage(cmd.Flags())
			return nil
		}

		if conf.metricsURI != "" {
			conf.AuthRequest.Count = 0 // assume infinite loops when setting prometheus export URL
			conf.metrics = prometheusExport(cmd.Context(), conf.metricsURI)
		}

		var wg errgroup.Group
		for i := range conf.AuthRequest.Concurrency {
			wg.Go(func() error {
				return authenticate(cmd.Context(), fmt.Sprintf("Client %d", i+1), conf)
			})
		}
		if err := wg.Wait(); err != nil {
			return fmt.Errorf("authenticating user: %w", err)
		}
		return nil
	}
	return cmd
}

type metrics struct {
	latency promsdk.Histogram
	errors  promsdk.Counter
}

// Errors safely increases the error counter.
func (m metrics) Errors(i float64) {
	if m.errors == nil {
		return
	}
	m.errors.Add(i)
}

// Latency safely records observed latency.
func (m metrics) Latency(i float64) {
	if m.latency == nil {
		return
	}
	m.latency.Observe(i)
}

func prometheusExport(ctx context.Context, addr string) metrics {
	var m metrics
	if addr == "" {
		return m
	}
	m.latency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace:   "zitcli",
		Subsystem:   "authenticate",
		Name:        "duration_seconds",
		Help:        "latency of authenticate calls",
		ConstLabels: nil,
		Buckets:     []float64{0.1, 0.5, 1, 2, 3, 5, 10, 20, 50, 100},
	})

	m.errors = promsdk.NewCounter(promsdk.CounterOpts{
		Namespace:   "zitcli",
		Subsystem:   "authenticate",
		Name:        "errors_total",
		Help:        "count of failed authenticate calls",
		ConstLabels: nil,
	})

	r := prometheus.NewRegistry()
	r.MustRegister(m.latency)
	r.MustRegister(m.errors)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
	srv := &http.Server{
		Addr:         addr,
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		Handler:      mux,
	}

	go func() {
		log.Printf("starting prometheus exporter on: %s/metrics\n", addr)
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatal("starting prometheus server: ", err)
		}
	}()

	return m
}

func authenticate(ctx context.Context, name string, conf authenticateConfig) error {
	u, err := zitadel.SanitizeURL(conf.AuthRequest.Address)
	if err != nil {
		conf.metrics.Errors(1)
		return err
	}
	client, err := zitadel.New(
		zitadel.WithHTTP(u),
		zitadel.WithGRPC(ctx, u, conf.AuthRequest.MachineAccessToken),
		zitadel.WithJWTAuthentication(conf.PrivateKey),
	)
	if err != nil {
		conf.metrics.Errors(1)
		return err
	}

	for i := 0; conf.AuthRequest.Count == 0 || i < conf.AuthRequest.Count; i++ {
		if ctx.Err() != nil {
			conf.metrics.Errors(1)
			return ctx.Err()
		}
		t := time.Now()
		if _, err := client.UsernamePasswordAuthenticate(ctx, conf.AuthRequest); err != nil {
			conf.metrics.Errors(1)
			return fmt.Errorf("authenticating with username and password: %w", err)
		}
		since := time.Since(t).Seconds()
		conf.metrics.Latency(since)
		if conf.AuthRequest.Count != 1 { // do not log this line if this is never repeated
			log.Printf("%s: Logged in after %0.1f seconds. Attempt: %d\n", name, since, i+1)
		}
	}

	return nil
}
