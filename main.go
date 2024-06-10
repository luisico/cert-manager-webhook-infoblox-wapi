package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	GroupNameEnvVarName = "GROUP_NAME"
	WebHookName         = "infoblox-wapi"
)

func main() {
	groupName := os.Getenv(GroupNameEnvVarName)
	if groupName == "" {
		logf.V(logf.ErrorLevel).ErrorS(nil, "environment variable '"+GroupNameEnvVarName+"' must be specified")
		os.Exit(1)
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.

	cmd.RunWebhookServer(groupName, &customDNSProviderSolver{})
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

type customDNSProviderRequest struct {
	client *kubernetes.Clientset

	// configuration
	config customDNSProviderRequestConfig

	// InfoBlox handler
	ibclient *ibclient.Connector
}

// customDNSProviderRequestConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderRequestConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	// internal values
	IssuerResourceNamespace string

	// config values
	Host                string                           `json:"host"`
	Version             string                           `json:"version"`
	Port                string                           `json:"port"`
	UsernameSecretRef   cmmeta.SecretKeySelector         `json:"usernameSecretRef"`
	PasswordSecretRef   cmmeta.SecretKeySelector         `json:"passwordSecretRef"`
	SecretRefNamespace  string                           `json:"secretRefNamespace"`
	View                string                           `json:"view"`
	SslVerify           bool                             `json:"sslVerify"`
	HTTPRequestTimeout  uint                             `json:"httpRequestTimeout"`
	HTTPPoolConnections uint                             `json:"httpPoolConnections"`
	RecordTTL           uint                             `json:"recordTTL"`
	RecordMapping       []customDNSProviderRecordMapping `json:"recordMapping"`
}

// record to map domain domain names
type customDNSProviderRecordMapping struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// initialize a default config
func (c *customDNSProviderRequest) setDefaultConfig() {
	c.config = customDNSProviderRequestConfig{
		Version:             "2.5",
		Port:                "443",
		SslVerify:           false,
		HTTPRequestTimeout:  60,
		HTTPPoolConnections: 10,
		RecordTTL:           300,
	}
}

// instantiate new request object
func NewRequest(client *kubernetes.Clientset) customDNSProviderRequest {

	req := customDNSProviderRequest{}
	req.client = client
	req.setDefaultConfig()

	return req
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return WebHookName
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {

	providerRequest := NewRequest(c.client)
	err := providerRequest.HandleRequest(ch)

	if err != nil {
		logf.V(logf.ErrorLevel).ErrorS(err, "failed to run present")
	}
	return err
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {

	providerRequest := NewRequest(c.client)
	err := providerRequest.HandleRequest(ch)

	if err != nil {
		logf.V(logf.ErrorLevel).ErrorS(err, "failed to run cleanup")
	}
	return err
}

func (c *customDNSProviderRequest) HandleRequest(ch *v1alpha1.ChallengeRequest) error {
	var err error

	logf.V(logf.InfoLevel).InfoS("handling TXT record request", "name", ch.ResolvedFQDN, "action", ch.Action, "key", ch.Key)

	recordName, err := c.initRequest(ch)
	if err != nil {
		return err
	}

	defer func() {
		if tempErr := c.finishRequest(); tempErr != nil {
			err = tempErr
		}
	}()

	recordRef, err := c.GetTXTRecord(recordName, ch.Key)
	if err != nil {
		return err
	}

	switch ch.Action {
	case v1alpha1.ChallengeActionPresent:
		if recordRef != "" {
			logf.V(logf.InfoLevel).InfoS("TXT record already present, skipping creation", "name", recordName, "ref", recordRef)
			return err
		}

		recordRef, err = c.CreateTXTRecord(recordName, ch.Key)
		if err != nil {
			return err
		}

		logf.V(logf.InfoLevel).InfoS("created new TXT record", "name", recordName, "ref", recordRef)

	case v1alpha1.ChallengeActionCleanUp:
		if recordRef == "" {
			logf.V(logf.InfoLevel).InfoS("TXT record not found, skipping deletion", "name", recordName, "text", ch.Key)
			return err
		}

		if err = c.DeleteTXTRecord(recordRef); err != nil {
			return err
		}

		logf.V(logf.InfoLevel).InfoS("deleted TXT record", "name", recordName, "ref", recordRef)
	default:
		return fmt.Errorf("handling webhook action '%s' is currently not implemented", ch.Action)
	}

	return err
}

// setup config and client at beginning of a request
func (c *customDNSProviderRequest) initRequest(ch *v1alpha1.ChallengeRequest) (string, error) {

	logf.V(logf.DebugLevel).InfoS("initializing request")

	if err := c.loadConfig(ch); err != nil {
		return "", err
	}

	// Initialize ibclient
	if err := c.getIbClient(); err != nil {
		return "", err
	}

	// Remove trailing dot and map record
	return c.mapRecord(strings.TrimSuffix(ch.ResolvedFQDN, ".")), nil
}

func (c *customDNSProviderRequest) finishRequest() error {
	logf.V(logf.DebugLevel).InfoS("performing InfoBlox logout")
	return c.ibclient.Logout()
}

func (c *customDNSProviderRequest) mapRecord(record string) string {
	for _, recordMapping := range c.config.RecordMapping {
		if strings.HasSuffix(record, recordMapping.From) {
			i := strings.LastIndex(record, recordMapping.From)
			mappedRecord := record[:i] + strings.Replace(record[i:], recordMapping.From, recordMapping.To, 1)

			logf.V(logf.InfoLevel).InfoS("mapping requested domain from '" + record + "' to '" + mappedRecord + "'")
			return mappedRecord
		}
	}
	logf.V(logf.DebugLevel).InfoS("no mapping for '" + record + "' found")
	return record
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func (c *customDNSProviderRequest) loadConfig(ch *v1alpha1.ChallengeRequest) error {

	// set namespace and default config values
	c.setDefaultConfig()
	c.config.IssuerResourceNamespace = ch.ResourceNamespace

	// handle the 'base case' where no configuration has been provided
	if ch.Config == nil {
		logf.V(logf.DebugLevel).InfoS("no webhook config provided")
		return nil
	}

	logf.V(logf.DebugLevel).InfoS("provided configuration", "config", ch.Config.Raw)

	if err := json.Unmarshal(ch.Config.Raw, &c.config); err != nil {
		return fmt.Errorf("error decoding solver config: %v", err)
	}

	return nil
}

// Initialize infoblox client connector
// Configuration can be set in the webhook `config` section.
// Two secretRefs are needed to securely pass infoblox credentials
func (c *customDNSProviderRequest) getIbClient() error {

	// Find secret credentials
	username, err := c.getSecret(c.config.UsernameSecretRef)
	if err != nil {
		return err
	}

	password, err := c.getSecret(c.config.PasswordSecretRef)
	if err != nil {
		return err
	}

	// set up client config
	hostConfig := ibclient.HostConfig{
		Host:     c.config.Host,
		Version:  c.config.Version,
		Port:     c.config.Port,
		Username: username,
		Password: password,
	}

	// define HTTPS transport options
	transportConfig := ibclient.NewTransportConfig(strconv.FormatBool(c.config.SslVerify), int(c.config.HTTPRequestTimeout), int(c.config.HTTPPoolConnections))

	logf.V(logf.DebugLevel).InfoS("initializing InfoBlox client")

	// Initialize ibclient
	c.ibclient, err = ibclient.NewConnector(hostConfig, transportConfig, &ibclient.WapiRequestBuilder{}, &ibclient.WapiHttpRequestor{})

	if err != nil {
		return err
	}

	return nil
}

// Resolve the value of a secret given a SecretKeySelector with name and key parameters
func (c *customDNSProviderRequest) getSecret(sel cmmeta.SecretKeySelector) (string, error) {
	secretNamespace := func() string {
		if c.config.SecretRefNamespace != "" {
			return c.config.SecretRefNamespace
		}
		return c.config.IssuerResourceNamespace
	}()

	secret, err := c.client.CoreV1().Secrets(secretNamespace).Get(context.Background(), sel.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	secretData, ok := secret.Data[sel.Key]
	if !ok {
		return "", err
	}

	return strings.TrimSuffix(string(secretData), "\n"), nil
}

// Get the ref for TXT record in InfoBlox given its name, text and view
func (c *customDNSProviderRequest) GetTXTRecord(name string, text string) (string, error) {
	var records []ibclient.RecordTXT
	params := map[string]string{
		"name": name,
		"text": text,
		"view": c.config.View,
	}

	logf.V(logf.DebugLevel).InfoS("looking up TXT record", "record", params)

	err := c.ibclient.GetObject(ibclient.NewRecordTXT(ibclient.RecordTXT{}), "", ibclient.NewQueryParams(false, params), &records)

	if len(records) > 0 {
		return records[0].Ref, err
	} else {
		return "", err
	}
}

// Create a TXT record in Infoblox
func (c *customDNSProviderRequest) CreateTXTRecord(name string, text string) (string, error) {

	newRecord := ibclient.NewRecordTXT(ibclient.RecordTXT{
		Name:   name,
		Text:   text,
		View:   c.config.View,
		Ttl:    c.config.RecordTTL,
		UseTtl: true,
	})

	logf.V(logf.DebugLevel).InfoS("creating TXT record", "record", newRecord)

	return c.ibclient.CreateObject(newRecord)
}

// Delete a TXT record in Infoblox by ref
func (c *customDNSProviderRequest) DeleteTXTRecord(ref string) error {

	logf.V(logf.DebugLevel).InfoS("deleting TXT record", "record", ref)

	_, err := c.ibclient.DeleteObject(ref)

	return err
}
