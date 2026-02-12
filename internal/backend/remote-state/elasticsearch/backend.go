// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package elasticsearch

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/zclconf/go-cty/cty"

	"github.com/hashicorp/terraform/internal/backend"
	"github.com/hashicorp/terraform/internal/backend/backendbase"
	"github.com/hashicorp/terraform/internal/configs/configschema"
	"github.com/hashicorp/terraform/internal/tfdiags"
)

const (
	defaultIndex = "terraform_remote_state"
)

// New creates a new backend for Elasticsearch remote state.
func New() backend.Backend {
	return &Backend{
		Base: backendbase.Base{
			Schema: &configschema.Block{
				Attributes: map[string]*configschema.Attribute{
					"endpoints": {
						Type:        cty.List(cty.String),
						Optional:    true,
						Description: "Elasticsearch cluster endpoints (e.g. [\"http://localhost:9200\"])",
					},
					"index": {
						Type:        cty.String,
						Optional:    true,
						Description: "Index name for Terraform state storage",
					},
					"username": {
						Type:        cty.String,
						Optional:    true,
						Description: "Username for Elasticsearch authentication",
					},
					"password": {
						Type:        cty.String,
						Optional:    true,
						Description: "Password for Elasticsearch authentication",
						Sensitive:   true,
					},
					"api_key": {
						Type:        cty.String,
						Optional:    true,
						Description: "API Key for Elasticsearch authentication (format: id:api_key or base64-encoded)",
						Sensitive:   true,
					},
					"bearer_token": {
						Type:        cty.String,
						Optional:    true,
						Description: "Bearer token for Elasticsearch authentication",
						Sensitive:   true,
					},
					"headers": {
						Type:        cty.Map(cty.String),
						Optional:    true,
						Description: "Custom headers to send with each Elasticsearch request",
					},
					"skip_cert_verification": {
						Type:        cty.Bool,
						Optional:    true,
						Description: "Whether to skip TLS certificate verification",
					},
					"ca_certificate_file": {
						Type:        cty.String,
						Optional:    true,
						Description: "Path to a PEM-encoded CA certificate file used to verify Elasticsearch server certificates",
					},
					"ca_certificate_pem": {
						Type:        cty.String,
						Optional:    true,
						Description: "A PEM-encoded CA certificate chain used to verify Elasticsearch server certificates",
					},
					"client_certificate_file": {
						Type:        cty.String,
						Optional:    true,
						Description: "Path to a PEM-encoded certificate file for mutual TLS authentication",
					},
					"client_certificate_pem": {
						Type:        cty.String,
						Optional:    true,
						Description: "A PEM-encoded certificate for mutual TLS authentication",
					},
					"client_private_key_file": {
						Type:        cty.String,
						Optional:    true,
						Description: "Path to a PEM-encoded private key file for mutual TLS authentication",
					},
					"client_private_key_pem": {
						Type:        cty.String,
						Optional:    true,
						Description: "A PEM-encoded private key for mutual TLS authentication",
						Sensitive:   true,
					},
				},
			},
			SDKLikeDefaults: backendbase.SDKLikeDefaults{
				"index": {
					EnvVars:  []string{"ELASTICSEARCH_INDEX"},
					Fallback: defaultIndex,
				},
				"username": {
					EnvVars: []string{"ELASTICSEARCH_USERNAME"},
				},
				"password": {
					EnvVars: []string{"ELASTICSEARCH_PASSWORD"},
				},
				"api_key": {
					EnvVars: []string{"ELASTICSEARCH_API_KEY"},
				},
				"bearer_token": {
					EnvVars: []string{"ELASTICSEARCH_BEARER_TOKEN"},
				},
				"skip_cert_verification": {
					EnvVars:  []string{"ELASTICSEARCH_SKIP_CERT_VERIFICATION", "ELASTICSEARCH_INSECURE"},
					Fallback: "false",
				},
				"ca_certificate_file": {
					EnvVars: []string{"ELASTICSEARCH_CA_CERTIFICATE_FILE"},
				},
				"ca_certificate_pem": {
					EnvVars: []string{"ELASTICSEARCH_CA_CERTIFICATE_PEM"},
				},
				"client_certificate_file": {
					EnvVars: []string{"ELASTICSEARCH_CLIENT_CERTIFICATE_FILE"},
				},
				"client_certificate_pem": {
					EnvVars: []string{"ELASTICSEARCH_CLIENT_CERTIFICATE_PEM"},
				},
				"client_private_key_file": {
					EnvVars: []string{"ELASTICSEARCH_CLIENT_PRIVATE_KEY_FILE"},
				},
				"client_private_key_pem": {
					EnvVars: []string{"ELASTICSEARCH_CLIENT_PRIVATE_KEY_PEM"},
				},
			},
		},
	}
}

type Backend struct {
	backendbase.Base

	// The fields below are set from configure
	client *elasticsearch.Client
	index  string
}

func (b *Backend) Configure(configVal cty.Value) tfdiags.Diagnostics {
	data := backendbase.NewSDKLikeData(configVal)

	// Get endpoints
	endpoints := []string{}
	endpointsAttr := configVal.GetAttr("endpoints")
	if !endpointsAttr.IsNull() && endpointsAttr.Type().IsListType() {
		for it := endpointsAttr.ElementIterator(); it.Next(); {
			_, val := it.Element()
			endpoints = append(endpoints, val.AsString())
		}
	}

	if len(endpoints) == 0 {
		if env := os.Getenv("ELASTICSEARCH_ENDPOINTS"); env != "" {
			for e := range strings.SplitSeq(env, ",") {
				endpoints = append(endpoints, strings.TrimSpace(e))
			}
		}
	}

	// Final fallback
	if len(endpoints) == 0 {
		endpoints = []string{"http://localhost:9200"}
	}

	b.index = data.String("index")

	// Validate index name according to Elasticsearch requirements
	if err := validateIndexName(b.index); err != nil {
		return backendbase.ErrorAsDiagnostics(err)
	}

	cfg := elasticsearch.Config{
		Addresses: endpoints,
	}

	username := data.String("username")
	password := data.String("password")
	apiKey := data.String("api_key")
	bearerToken := data.String("bearer_token")

	authMethodsCount := 0
	if username != "" {
		authMethodsCount++
	}
	if apiKey != "" {
		authMethodsCount++
	}
	if bearerToken != "" {
		authMethodsCount++
	}

	if authMethodsCount > 1 {
		return backendbase.ErrorAsDiagnostics(
			fmt.Errorf("only one authentication method can be used: username/password, api_key, or bearer_token"),
		)
	}

	if username != "" {
		cfg.Username = username
		cfg.Password = password
	} else if apiKey != "" {
		cfg.APIKey = apiKey
	} else if bearerToken != "" {
		cfg.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))
	}

	headersAttr := configVal.GetAttr("headers")
	if !headersAttr.IsNull() && headersAttr.Type().IsMapType() {
		for it := headersAttr.ElementIterator(); it.Next(); {
			key, val := it.Element()
			headerName := strings.TrimSpace(key.AsString())
			headerValue := strings.TrimSpace(val.AsString())
			cfg.Header.Add(headerName, headerValue)
		}
	}

	caCert, tlsConfig, err := b.configureTLS(&data)
	if err != nil {
		return backendbase.ErrorAsDiagnostics(err)
	}

	if len(caCert) > 0 {
		cfg.CACert = caCert
	}

	if tlsConfig != nil {
		if cfg.Transport == nil {
			cfg.Transport = http.DefaultTransport.(*http.Transport).Clone()
		}
		cfg.Transport.(*http.Transport).TLSClientConfig = tlsConfig
	}

	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return backendbase.ErrorAsDiagnostics(
			fmt.Errorf("failed to create Elasticsearch client: %w", err),
		)
	}

	b.client = client

	if err := b.ensureIndex(); err != nil {
		return backendbase.ErrorAsDiagnostics(
			fmt.Errorf("failed to initialize Elasticsearch: %w", err),
		)
	}

	return nil
}

// configureTLS configures TLS settings and returns CA cert data and TLS config
// Returns: (caCertData, tlsConfig, error)
// The caCertData is returned separately to use with elasticsearch.Config.CACert
// The tlsConfig is only created when InsecureSkipVerify or client certificates are needed
func (b *Backend) configureTLS(data *backendbase.SDKLikeData) ([]byte, *tls.Config, error) {
	skipCertVerification := data.Bool("skip_cert_verification")

	// Get CA certificate (file path or PEM data)
	caFile := data.String("ca_certificate_file")
	caPem := data.String("ca_certificate_pem")

	// Get client certificate (file path or PEM data)
	certFile := data.String("client_certificate_file")
	certPem := data.String("client_certificate_pem")

	// Get client private key (file path or PEM data)
	keyFile := data.String("client_private_key_file")
	keyPem := data.String("client_private_key_pem")

	// Validate that file and PEM options are not both set for the same certificate
	if caFile != "" && caPem != "" {
		return nil, nil, fmt.Errorf("ca_certificate_file and ca_certificate_pem cannot both be set")
	}
	if certFile != "" && certPem != "" {
		return nil, nil, fmt.Errorf("client_certificate_file and client_certificate_pem cannot both be set")
	}
	if keyFile != "" && keyPem != "" {
		return nil, nil, fmt.Errorf("client_private_key_file and client_private_key_pem cannot both be set")
	}

	// Validate that both certificate and key are provided together
	hasCert := certFile != "" || certPem != ""
	hasKey := keyFile != "" || keyPem != ""
	if hasCert && !hasKey {
		return nil, nil, fmt.Errorf("client certificate is set but client private key is not")
	}
	if hasKey && !hasCert {
		return nil, nil, fmt.Errorf("client private key is set but client certificate is not")
	}

	// Load CA certificate data
	var caCertData []byte
	var err error
	if caFile != "" {
		caCertData, err = os.ReadFile(caFile)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read CA certificate file: %w", err)
		}
	} else if caPem != "" {
		caCertData = []byte(caPem)
	}

	// Only create TLS config if we need InsecureSkipVerify or client certificates
	var tlsConfig *tls.Config
	if skipCertVerification || hasCert {
		tlsConfig = &tls.Config{}

		if skipCertVerification {
			tlsConfig.InsecureSkipVerify = true
		}

		if hasCert {
			var clientCertData []byte
			var clientKeyData []byte

			if certFile != "" {
				clientCertData, err = os.ReadFile(certFile)
				if err != nil {
					return nil, nil, fmt.Errorf("unable to read client certificate file: %w", err)
				}
			} else {
				clientCertData = []byte(certPem)
			}

			if keyFile != "" {
				clientKeyData, err = os.ReadFile(keyFile)
				if err != nil {
					return nil, nil, fmt.Errorf("unable to read client private key file: %w", err)
				}
			} else {
				clientKeyData = []byte(keyPem)
			}

			certificate, err := tls.X509KeyPair(clientCertData, clientKeyData)
			if err != nil {
				return nil, nil, fmt.Errorf("cannot load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{certificate}
		}
	}

	return caCertData, tlsConfig, nil
}

// ensureIndex ensures the Elasticsearch index exists
func (b *Backend) ensureIndex() error {
	client := &RemoteClient{
		Client: b.client,
		Index:  b.index,
	}

	return client.ensureIndex()
}

// validateIndexName validates an Elasticsearch index name according to the naming restrictions
// See: https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-create-index.html#indices-create-api-path-params
func validateIndexName(name string) error {
	if name == "" {
		return fmt.Errorf("index name cannot be empty")
	}

	if len(name) > 255 {
		return fmt.Errorf("index name cannot be longer than 255 bytes")
	}

	if name != strings.ToLower(name) {
		return fmt.Errorf("index name must be lowercase")
	}

	if name == "." || name == ".." {
		return fmt.Errorf("index name cannot be '.' or '..'")
	}

	if strings.HasPrefix(name, "-") || strings.HasPrefix(name, "_") || strings.HasPrefix(name, "+") {
		return fmt.Errorf("index name cannot start with '-', '_', or '+'")
	}

	invalidChars := []string{"\\", "/", "*", "?", "\"", "<", ">", "|", " ", ",", "#"}
	for _, char := range invalidChars {
		if strings.Contains(name, char) {
			return fmt.Errorf("index name cannot contain '%s'", char)
		}
	}

	return nil
}
