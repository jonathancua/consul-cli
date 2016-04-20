package commands

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type consul struct {
	configFile string
	env        string
	address    string
	sslEnabled bool
	sslVerify  bool
	sslCert    string
	sslKey     string
	sslCaCert  string
	token      string
	tokenFile  string
	auth       *auth
	tlsConfig  *tls.Config

	dc        string
	waitIndex uint64
}

type configFromFile struct {
	address    string
	sslEnabled bool
	sslVerify  bool
	sslCert    string
	sslKey     string
	sslCaCert  string
	token      string
}

func (c *Cmd) ACL() (*consulapi.ACL, error) {
	consul, err := c.Client()
	if err != nil {
		return nil, err
	}

	return consul.ACL(), nil
}

func (c *Cmd) Agent() (*consulapi.Agent, error) {
	consul, err := c.Client()
	if err != nil {
		return nil, err
	}

	return consul.Agent(), nil
}

func (c *Cmd) Catalog() (*consulapi.Catalog, error) {
	consul, err := c.Client()
	if err != nil {
		return nil, err
	}

	return consul.Catalog(), nil
}

func (c *Cmd) Coordinate() (*consulapi.Coordinate, error) {
	consul, err := c.Client()
	if err != nil {
		return nil, err
	}

	return consul.Coordinate(), nil
}

func (c *Cmd) Health() (*consulapi.Health, error) {
	consul, err := c.Client()
	if err != nil {
		return nil, err
	}

	return consul.Health(), nil
}

func (c *Cmd) KV() (*consulapi.KV, error) {
	consul, err := c.Client()
	if err != nil {
		return nil, err
	}

	return consul.KV(), nil
}

func (c *Cmd) Session() (*consulapi.Session, error) {
	consul, err := c.Client()
	if err != nil {
		return nil, err
	}

	return consul.Session(), nil
}

func (c *Cmd) Status() (*consulapi.Status, error) {
	consul, err := c.Client()
	if err != nil {
		return nil, err
	}

	return consul.Status(), nil
}

func (c *Cmd) Client() (*consulapi.Client, error) {
	config := consulapi.DefaultConfig()
	csl := c.consul
	csl.tlsConfig = new(tls.Config)
	configFile := c.GetConfig()

	// The address in the file takes precedence than the
	// one supplied on the command-line
	if configFile.address != "" {
		config.Address = configFile.address
	} else if csl.address != "" {
		config.Address = c.consul.address
	}

	if configFile.token != "" {
		config.Token = configFile.token
	} else if csl.token != "" {
		config.Token = csl.token
	}

	if configFile.sslEnabled || csl.sslEnabled {
		config.Scheme = "https"
	}

	var sslVerify bool
	if configFile.sslVerify || csl.sslVerify {
		sslVerify = true
	}

	var sslCert string
	if configFile.sslCert != "" {
		sslCert = configFile.sslCert
	} else if csl.sslCert != "" {
		sslCert = csl.sslCert
	}

	var sslKey string
	if configFile.sslKey != "" {
		sslKey = configFile.sslKey
	} else if csl.sslKey != "" {
		sslKey = csl.sslKey
	}

	var sslCaCert string
	if configFile.sslCaCert != "" {
		sslCaCert = configFile.sslCaCert
	} else if csl.sslCaCert != "" {
		sslCaCert = csl.sslCaCert
	}

	if config.Scheme == "https" {
		if sslCert != "" {
			if sslKey == "" {
				return nil, errors.New("--ssl-key must be provided in order to use certificates for authentication")
			}
			clientCert, err := tls.LoadX509KeyPair(sslCert, sslKey)
			if err != nil {
				return nil, err
			}

			csl.tlsConfig.Certificates = []tls.Certificate{clientCert}
			csl.tlsConfig.BuildNameToCertificate()
		}

		if sslVerify {
			if sslCaCert == "" {
				return nil, errors.New("--ssl-ca-cert must be provided in order to use certificates for verification")
			}

			caCert, err := ioutil.ReadFile(sslCaCert)
			if err != nil {
				return nil, err
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			csl.tlsConfig.RootCAs = caCertPool
		}
	}

	transport := new(http.Transport)
	transport.TLSClientConfig = csl.tlsConfig

	if !sslVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}
	config.HttpClient.Transport = transport

	if csl.auth.Enabled {
		config.HttpAuth = &consulapi.HttpBasicAuth{
			Username: csl.auth.Username,
			Password: csl.auth.Password,
		}
	}

	client, err := consulapi.NewClient(config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (c *Cmd) GetConfig() *configFromFile {
	config := &configFromFile{}
	viper.SetConfigName(".consul-cli")
	viper.AddConfigPath("$HOME")
	viper.ReadInConfig()

	consulAddrStr := fmt.Sprintf("%s.consul", c.consul.env)
	consulTokenStr := fmt.Sprintf("%s.token", c.consul.env)
	consulSslStr := fmt.Sprintf("%s.ssl", c.consul.env)
	consulSslVerifyStr := fmt.Sprintf("%s.ssl-verify", c.consul.env)
	consulSslCertStr := fmt.Sprintf("%s.ssl-cert", c.consul.env)
	consulSslKeyStr := fmt.Sprintf("%s.ssl-key", c.consul.env)
	consulSslCaCertStr := fmt.Sprintf("%s.ssl-ca-cert", c.consul.env)

	if viper.GetString(consulAddrStr) != "" {
		config.address = viper.GetString(consulAddrStr)
	}
	if viper.GetBool(consulSslStr) {
		config.sslEnabled = viper.GetBool(consulSslStr)
	}
	if viper.GetBool(consulSslVerifyStr) {
		config.sslVerify = viper.GetBool(consulSslVerifyStr)
	}
	if viper.GetString(consulSslCertStr) != "" {
		config.sslCert = viper.GetString(consulSslCertStr)
	}
	if viper.GetString(consulSslCaCertStr) != "" {
		config.sslKey = viper.GetString(consulSslKeyStr)
	}
	if viper.GetString(consulSslCaCertStr) != "" {
		config.sslCaCert = viper.GetString(consulSslCaCertStr)
	}
	if viper.GetString(consulTokenStr) != "" {
		config.token = viper.GetString(consulTokenStr)
	}

	return config
}

func (c *Cmd) WriteOptions() *consulapi.WriteOptions {
	csl := c.consul

	writeOpts := new(consulapi.WriteOptions)
	if csl.token != "" {
		writeOpts.Token = csl.token
	}

	if csl.dc != "" {
		writeOpts.Datacenter = csl.dc
	}

	return writeOpts
}

func (c *Cmd) QueryOptions() *consulapi.QueryOptions {
	csl := c.consul

	queryOpts := new(consulapi.QueryOptions)
	if csl.token != "" {
		queryOpts.Token = csl.token
	}

	if csl.dc != "" {
		queryOpts.Datacenter = csl.dc
	}

	if csl.waitIndex != 0 {
		queryOpts.WaitIndex = csl.waitIndex
	}

	return queryOpts
}

func (c *Cmd) AddDatacenterOption(cmd *cobra.Command) {
	cmd.Flags().StringVar(&c.consul.dc, "datacenter", "", "Consul data center")
}

func (c *Cmd) AddWaitIndexOption(cmd *cobra.Command) {
	cmd.Flags().Uint64Var(&c.consul.waitIndex, "wait-index", 0, "Only return if ModifyIndex is greater than <index>")
}

func NewConsul() *consul {
	return &consul{
		auth: new(auth),
	}
}

type auth struct {
	Enabled  bool
	Username string
	Password string
}

func (a *auth) Set(value string) error {
	a.Enabled = true

	if strings.Contains(value, ":") {
		split := strings.SplitN(value, ":", 2)
		a.Username = split[0]
		a.Password = split[1]
	} else {
		a.Username = value
	}

	return nil
}

func (a *auth) String() string {
	if a.Password == "" {
		return a.Username
	}

	return fmt.Sprintf("%s:%s", a.Username, a.Password)
}

func (a *auth) Type() string {
	return "auth"
}
