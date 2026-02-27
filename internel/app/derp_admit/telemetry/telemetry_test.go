package telemetry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/telemetry"

	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

func TestSetupOTelDisabled(t *testing.T) {
	cfg := config.Config{
		OTELEnabled:     false,
		OTELServiceName: "derp-admit-test",
		OTELSampleRatio: 1.0,
	}

	shutdown, err := telemetry.SetupOTel(context.Background(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("SetupOTel disabled returned error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown disabled returned error: %v", err)
	}
}

func TestSetupOTelEnabledWithLocalCollector(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	u, err := url.Parse(collector.URL)
	if err != nil {
		t.Fatalf("parse collector URL: %v", err)
	}

	cfg := config.Config{
		OTELEnabled:     true,
		OTELServiceName: "derp-admit-test",
		OTLPEndpoint:    u.Host,
		OTLPInsecure:    true,
		OTELSampleRatio: 1.0,
	}

	shutdown, err := telemetry.SetupOTel(context.Background(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("SetupOTel enabled returned error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, span := otel.Tracer("test").Start(ctx, "test-span")
	span.End()

	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown enabled returned error: %v", err)
	}
}
