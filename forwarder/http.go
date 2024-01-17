package forwarder

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/bangunindo/trap2json/helper"
	"github.com/carlmjohnson/requests"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type HTTPMethod int

const (
	HTTPMethodPost HTTPMethod = iota
	HTTPMethodGet
	HTTPMethodPut
)

func (h *HTTPMethod) String() string {
	switch *h {
	case HTTPMethodPost:
		return "POST"
	case HTTPMethodGet:
		return "GET"
	case HTTPMethodPut:
		return "PUT"
	default:
		return ""
	}
}

func (h *HTTPMethod) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "post":
		*h = HTTPMethodPost
	case "get":
		*h = HTTPMethodGet
	case "put":
		*h = HTTPMethodPut
	default:
		return errors.Errorf("unsupported HTTPMethod: %s", string(text))
	}
	return nil
}

type HTTPBasicAuth struct {
	Username string
	Password string
}

type HTTPConfig struct {
	URL       string `mapstructure:"url"`
	Method    HTTPMethod
	Headers   map[string][]string
	BasicAuth *HTTPBasicAuth `mapstructure:"basic_auth"`
	Tls       *Tls
	Proxy     string
	Timeout   helper.Duration
}

type HTTP struct {
	Base

	builder *requests.Builder
}

func (h *HTTP) Run() {
	defer h.cancel()
	defer h.logger.Info().Msg("forwarder exited")
	h.logger.Info().Msg("starting forwarder")

	builder := requests.
		URL(h.config.HTTP.URL).
		Method(h.config.HTTP.Method.String()).
		Headers(h.config.HTTP.Headers)
	transport := &http.Transport{}
	if h.config.HTTP.BasicAuth != nil {
		builder = builder.BasicAuth(h.config.HTTP.BasicAuth.Username, h.config.HTTP.BasicAuth.Password)
	}
	if h.config.HTTP.Tls != nil {
		tlsConf := &tls.Config{
			InsecureSkipVerify: h.config.HTTP.Tls.InsecureSkipVerify,
		}
		if h.config.HTTP.Tls.CaCert != "" {
			ca, err := os.ReadFile(h.config.HTTP.Tls.CaCert)
			if err != nil {
				h.logger.Fatal().Err(err).Msg("failed reading ca certificate")
			}
			caCerts := x509.NewCertPool()
			caCerts.AppendCertsFromPEM(ca)
			tlsConf.RootCAs = caCerts
		}
		if h.config.HTTP.Tls.ClientCert != "" &&
			h.config.HTTP.Tls.ClientKey != "" {
			cert, err := tls.LoadX509KeyPair(h.config.HTTP.Tls.ClientCert, h.config.HTTP.Tls.ClientKey)
			if err != nil {
				h.logger.Fatal().Err(err).Msg("failed reading client certificate")
			}
			tlsConf.Certificates = []tls.Certificate{cert}
		}
		transport.TLSClientConfig = tlsConf
	}
	if h.config.HTTP.Proxy != "" {
		proxyUrl, err := url.Parse(h.config.HTTP.Proxy)
		if err != nil {
			h.logger.Fatal().Err(err).Msg("proxy url is not in the correct format")
		}
		transport.Proxy = http.ProxyURL(proxyUrl)
	}
	builder = builder.Transport(transport)

	for m := range h.ReceiveChannel() {
		m.Compile(h.CompilerConf)
		if m.Metadata.Skip {
			h.ctrFiltered.Inc()
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), h.config.HTTP.Timeout.Duration)
		if err := builder.BodyBytes(m.Metadata.MessageJSON).Fetch(ctx); err != nil {
			cancel()
			h.Retry(m, err)
		} else {
			cancel()
			h.ctrSucceeded.Inc()
		}
	}
}

func NewHTTP(c Config, idx int) Forwarder {
	fwd := &HTTP{
		Base: NewBase(c, idx),
	}
	go fwd.Run()
	return fwd
}
