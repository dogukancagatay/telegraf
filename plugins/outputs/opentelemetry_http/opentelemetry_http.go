//go:generate ../../../tools/readme_config_includer/generator
package opentelemetry_http

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"

	"github.com/influxdata/influxdb-observability/influx2otel"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/plugins/common/proxy"
	"github.com/influxdata/telegraf/plugins/common/tls"
	"github.com/influxdata/telegraf/plugins/outputs"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/metric"
)

//go:embed sample.conf
var sampleConfig string

const (
	defaultEndpointURL = "http://localhost:4318/v1/metrics"
	defaultTimeout     = config.Duration(5 * time.Second)
)

type OpenTelemetryHttp struct {
	EndpointURL string `toml:"url"`

	Timeout     config.Duration           `toml:"timeout"`
	Compression string                    `toml:"compression"`
	Username    config.Secret             `toml:"username"`
	Password    config.Secret             `toml:"password"`
	BearerToken config.Secret             `toml:"bearer_token"`
	Headers     map[string]*config.Secret `toml:"headers"`

	tls.ClientConfig
	proxy.HTTPProxy

	Log telegraf.Logger `toml:"-"`

	metricsConverter *influx2otel.LineProtocolToOtelMetrics
	httpExporter     *otlpmetrichttp.Exporter
	meterProvider    *metric.MeterProvider
}

func (*OpenTelemetryHttp) SampleConfig() string {
	return sampleConfig
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (o *OpenTelemetryHttp) Connect() error {
	logger := &otelLogger{o.Log}
	requestHeaders := make(map[string]string)

	if o.EndpointURL == "" {
		o.EndpointURL = defaultEndpointURL
	}

	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}

	if o.Compression == "" || o.Compression.lower() == "none" {
		o.Compression = otlpmetrichttp.NoCompression
	} else if o.Compression == "gzip" {
		o.Compression = otlpmetrichttp.CompressionGzip
	} else {
		return fmt.Errorf("invalid compression: %s", o.Compression)
	}

	if o.Headers != nil {
		for k, v := range h.Headers {
			secret, err := v.Get()
			if err != nil {
				return err
			}

			headerVal := secret.String()
			requestHeaders[k] = headerVal
			secret.Destroy()
		}
	}

	if !o.Username.Empty() && !o.Password.Empty() {
		requestHeaders["Authorization"] = "Basic " + BasicAuth(o.Username, o.Password)
		o.Username.Destroy()
		o.Password.Destroy()
	}

	if !o.BearerToken.Empty() {
		requestHeaderss["Authorization"] = "Bearer " + o.BearerToken
		o.BearerToken.Destroy()
	}

	o.metricsConverter, err := influx2otel.NewLineProtocolToOtelMetrics(logger)
	if err != nil {
		return err
	}

	// Setup HTTP exporter options
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpointURL(o.EndpointURL),
		otlpmetrichttp.WithCompressor(o.Compression),
		otlpmetrichttp.WithTimeout(o.Timeout),
		otlpmetrichttp.WithHeaders(requestHeaders),
		otlpmetrichttp.WithLogger(logger),
		otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{
			// Enabled indicates whether to not retry sending batches in case
			// of export failure.
			Enabled: false,
			// InitialInterval the time to wait after the first failure before
			// retrying.
			InitialInterval: 1 * time.Second,
			// MaxInterval is the upper bound on backoff interval. Once this
			// value is reached the delay between consecutive retries will
			// always be `MaxInterval`.
			MaxInterval: 10 * time.Second,
			// MaxElapsedTime is the maximum amount of time (including retries)
			// spent trying to send a request/batch. Once this value is
			// reached, the data is discarded.
			MaxElapsedTime: 20 * time.Second,
		}),
	}

	// Setup TLS config
	if tlsConfig, err := o.ClientConfig.TLSConfig(); err != nil {
		return err
	} else if tlsConfig != nil {
		opts.append(otlpmetrichttp.WithTLSClientConfig(o.ClientConfig.tlsConfig))
	} else {
		opts.append(otlpmetrichttp.WithInsecure())
	}

	if httpProxy, err := o.HTTPProxy.Proxy(); err != nil {
		return err
	} else if httpProxy != nil {
		opts.append(otlpmetrichttp.WithProxy(httpProxy))
	}

	httpExporter, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return err
	}

	o.meterProvider := metric.NewMeterProvider(metric.WithReader(metric.NewPeriodicReader(exp)))

	return nil
}

func (o *OpenTelemetryHttp) Close() error {
	ctx := context.Background()
	if o.meterProvider != nil {
		if err := o.meterProvider.Shutdown(ctx); err != nil {
			o.meterProvider = nil
			return err
		}
	}
	return nil
}

func (o *OpenTelemetry) Write(metrics []telegraf.Metric) error {
	metricBatch := make(map[int64][]telegraf.Metric)
	timestamps := []int64{}
	for _, metric := range metrics {
		timestamp := metric.Time().UnixNano()
		if existingSlice, ok := metricBatch[timestamp]; ok {
			metricBatch[timestamp] = append(existingSlice, metric)
		} else {
			metricBatch[timestamp] = []telegraf.Metric{metric}
			timestamps = append(timestamps, timestamp)
		}
	}

	// sort the timestamps we collected
	sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })

	o.Log.Debugf("Received %d metrics and split into %d groups by timestamp", len(metrics), len(metricBatch))
	for _, timestamp := range timestamps {
		if err := o.sendBatch(metricBatch[timestamp]); err != nil {
			return err
		}
	}

	return nil
}

func (h *HTTP) writeMetric(reqBody []byte) error {
	var reqBodyBuffer io.Reader = bytes.NewBuffer(reqBody)

	var err error
	if h.ContentEncoding == "gzip" {
		rc := internal.CompressWithGzip(reqBodyBuffer)
		defer rc.Close()
		reqBodyBuffer = rc
	}

	var payloadHash *string
	if h.awsCfg != nil {
		// We need a local copy of the full buffer, the signature scheme requires a sha256 of the request body.
		buf := new(bytes.Buffer)
		_, err = io.Copy(buf, reqBodyBuffer)
		if err != nil {
			return err
		}

		sum := sha256.Sum256(buf.Bytes())
		reqBodyBuffer = buf

		// sha256 is hex encoded
		hash := hex.EncodeToString(sum[:])
		payloadHash = &hash
	}

	req, err := http.NewRequest(h.Method, h.URL, reqBodyBuffer)
	if err != nil {
		return err
	}

	if h.awsCfg != nil {
		signer := v4.NewSigner()
		ctx := context.Background()

		credentials, err := h.awsCfg.Credentials.Retrieve(ctx)
		if err != nil {
			return err
		}

		err = signer.SignHTTP(ctx, credentials, req, *payloadHash, h.AwsService, h.Region, time.Now().UTC())
		if err != nil {
			return err
		}
	}

	if !h.Username.Empty() || !h.Password.Empty() {
		username, err := h.Username.Get()
		if err != nil {
			return fmt.Errorf("getting username failed: %w", err)
		}
		password, err := h.Password.Get()
		if err != nil {
			username.Destroy()
			return fmt.Errorf("getting password failed: %w", err)
		}
		req.SetBasicAuth(username.String(), password.String())
		username.Destroy()
		password.Destroy()
	}

	// google api auth
	if h.CredentialsFile != "" {
		token, err := h.getAccessToken(context.Background(), h.URL)
		if err != nil {
			return err
		}
		token.SetAuthHeader(req)
	}

	req.Header.Set("User-Agent", internal.ProductToken())
	req.Header.Set("Content-Type", defaultContentType)
	if h.ContentEncoding == "gzip" {
		req.Header.Set("Content-Encoding", "gzip")
	}

	for k, v := range h.Headers {
		secret, err := v.Get()
		if err != nil {
			return err
		}

		headerVal := secret.String()
		if strings.EqualFold(k, "host") {
			req.Host = headerVal
		}
		req.Header.Set(k, headerVal)

		secret.Destroy()
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		for _, nonRetryableStatusCode := range h.NonRetryableStatusCodes {
			if resp.StatusCode == nonRetryableStatusCode {
				h.Log.Errorf("Received non-retryable status %v. Metrics are lost.", resp.StatusCode)
				return nil
			}
		}

		errorLine := ""
		scanner := bufio.NewScanner(io.LimitReader(resp.Body, maxErrMsgLen))
		if scanner.Scan() {
			errorLine = scanner.Text()
		}

		return fmt.Errorf("when writing to [%s] received status code: %d. body: %s", h.URL, resp.StatusCode, errorLine)
	}

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("when writing to [%s] received error: %w", h.URL, err)
	}

	return nil
}

func init() {
	outputs.Add("opentelemetry_http", func() telegraf.Output {
		return &OpenTelemetryHttp{
			URL:         defaultURL,
			Timeout:     defaultTimeout,
			Compression: defaultCompression,
		}
	})
}
