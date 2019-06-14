package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/discovery/refresh"
	"github.com/prometheus/prometheus/discovery/targetgroup"
	"github.com/prometheus/prometheus/documentation/examples/custom-sd/adapter"
)

type Hosts struct {
	Host []Host
}

type Host struct {
	Address        string
	Cluster        Cluster
	ExternalStatus string `json:"external_status,omitempty"`
	ID             string
	Libvirt        Version `json:"libvirt_version,omitempty"`
	Name           string
	Nics           Nics
	Status         string
	Tags           Tags
	Type           string
	Version        Version
}

type Nics struct {
	HostNic []Nic `json:"host_nic,omitempty"`
}

type Nic struct {
	BootProtocol string
	Bridged      string
	IP           IP
	IPv6         IP
	Mac          Mac
	Name         string
	Status       string
}

type IP struct {
	Address string
	Gateway string
	Netmask string
	Version string
}

type Mac struct {
	Address string
}

type Tags struct {
	Tag []Tag
}

type Tag struct {
	Name string
}

type Version struct {
	FullVersion string `json:"full_version,omitempty"`
}

type Cluster struct {
	ID   string
	Name string
}

type Config struct {
	Logger         log.Logger
	Target         string
	URL            *url.URL
	User           string
	Password       string
	NoVerify       bool
	EngineCA       string
	UpdateInterval time.Duration
	TargetPort     string
}

func main() {
	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	logger = log.With(logger, "ts", log.DefaultTimestamp, "caller", log.DefaultCaller)
	err := run(logger)
	if err != nil {
		logger.Log("err", err)
		os.Exit(1)
	}
}

func run(logger log.Logger) error {
	target := flag.String("output", "engine-hosts.json", "target for the configuration file")
	engineURL := flag.String("engine-url", "https://localhost:8443", "Engine URL")
	engineUser := flag.String("engine-user", "admin@internal", "Engine user")
	enginePassword := flag.String("engine-password", "", "Engine password. Consider using ENGINE_PASSWORD environment variable to set this")
	noVerify := flag.Bool("no-verify", false, "Don't verify the engine certificate")
	engineCa := flag.String("engine-ca", "/etc/pki/ovirt-engine/ca.pem", "Path to engine ca certificate")
	updateInterval := flag.Int("update-interval", 60, "Update interval for host discovery in seconds")
	targetPort := flag.Int("host-port", 8181, "Port where Prometheus metrics are exposed on the hosts")
	flag.Parse()

	if *enginePassword == "" {
		*enginePassword = os.Getenv("ENGINE_PASSWORD")
	}
	if *enginePassword == "" {
		return errors.New("No engine password supplied")
	}

	u, err := url.Parse(*engineURL)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Failed to parse URL %s", *engineURL))
	}
	if u.Scheme != "https" {
		return errors.New("Only URLs starting with 'https' are supported")
	}

	config := Config{Target: *target,
		URL:            u,
		User:           *engineUser,
		Password:       *enginePassword,
		NoVerify:       *noVerify,
		EngineCA:       *engineCa,
		UpdateInterval: time.Duration(*updateInterval) * time.Second,
		TargetPort:     strconv.Itoa(*targetPort),
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.NoVerify,
	}
	if !config.NoVerify {
		roots := x509.NewCertPool()
		ca, err := ioutil.ReadFile(config.EngineCA)
		if err != nil {
			return err
		}
		if ok := roots.AppendCertsFromPEM(ca); !ok {
			return errors.New("Could not load root CA certificate")
		}

		tlsConfig.RootCAs = roots
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	discoverer := refresh.NewDiscovery(
		logger,
		"ovirt",
		time.Duration(config.UpdateInterval),
		refresher(client, &config, logger),
	)

	ctx := context.Background()
	sdAdapter := adapter.NewAdapter(ctx, *target, "ovirt", discoverer, logger)
	sdAdapter.Run()

	<-ctx.Done()

	return nil
}

var (
	invalidLabelCharRE = regexp.MustCompile(`[^a-zA-Z0-9_]`)

	oVirtPrefix = model.MetaLabelPrefix + "ovirt_"

	clusterPrefix    = oVirtPrefix + "cluster_"
	clusterIDLabel   = clusterPrefix + "id"
	clusterNameLabel = clusterPrefix + "name"

	hostPrefix              = oVirtPrefix + "host_"
	hostAddressLabel        = hostPrefix + "address"
	hostIDLabel             = hostPrefix + "id"
	hostNameLabel           = hostPrefix + "name"
	hostExternalStatusLabel = hostPrefix + "external_status"
	hostStatusLabel         = hostPrefix + "status"
	hostVersionLabel        = hostPrefix + "version"
	hostLibvirtLabel        = hostPrefix + "libvirt_version"
	hostTypeLabel           = hostPrefix + "type"
	hostTagsPrefix          = hostPrefix + "tags_"

	nicPrefix            = oVirtPrefix + "nic_"
	nicBootProtocolLabel = nicPrefix + "boot_protocol"
	nicBridgedLabel      = nicPrefix + "bridged"
	nicGatewayLabel      = nicPrefix + "gateway"
	nicMacAddressLabel   = nicPrefix + "mac_address"
	nicNameLabel         = nicPrefix + "name"
	nicNetmaskLabel      = nicPrefix + "netmask"
	nicStatusLabel       = nicPrefix + "status"
)

func refresher(client *http.Client, config *Config, logger log.Logger) func(ctx context.Context) ([]*targetgroup.Group, error) {
	last := make(map[string]struct{})

	return func(ctx context.Context) ([]*targetgroup.Group, error) {
		u, err := config.URL.Parse("/ovirt-engine/api/hosts")
		if err != nil {
			logger.Log("msg", "Failed to parse API URL", "err", err)
			return nil, err
		}
		q := u.Query()
		q.Set("follow", "cluster,tags,nics")
		u.RawQuery = q.Encode()

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			logger.Log("msg", "Failed to create API request", "err", err)
			return nil, err
		}
		req.Header.Add("Accept", "application/json")
		req.SetBasicAuth(config.User, config.Password)

		res, err := client.Do(req)
		if err != nil {
			logger.Log("msg", "Request to API failed", "err", err)
			return nil, err
		}

		b, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			logger.Log("msg", "Failed to read API response", "err", err)
			return nil, err
		}

		var hosts Hosts
		err = json.Unmarshal(b, &hosts)
		if err != nil {
			logger.Log("msg", "Failed to unmarshal API response", "err", err)
			return nil, err
		}

		// TODO: add network labels
		present := make(map[string]struct{}, len(hosts.Host))
		tgs := make([]*targetgroup.Group, 0, len(hosts.Host))
		for _, host := range hosts.Host {
			present[host.ID] = struct{}{}
			group := &targetgroup.Group{
				Source: host.ID,
				Labels: model.LabelSet{
					model.LabelName(clusterIDLabel):   model.LabelValue(host.Cluster.ID),
					model.LabelName(clusterNameLabel): model.LabelValue(host.Cluster.Name),

					model.LabelName(hostAddressLabel):        model.LabelValue(host.Address),
					model.LabelName(hostIDLabel):             model.LabelValue(host.ID),
					model.LabelName(hostNameLabel):           model.LabelValue(host.Name),
					model.LabelName(hostExternalStatusLabel): model.LabelValue(host.ExternalStatus),
					model.LabelName(hostStatusLabel):         model.LabelValue(host.Status),
					model.LabelName(hostVersionLabel):        model.LabelValue(host.Version.FullVersion),
					model.LabelName(hostLibvirtLabel):        model.LabelValue(host.Libvirt.FullVersion),
					model.LabelName(hostTypeLabel):           model.LabelValue(host.Type),
				},
			}
			for _, t := range host.Tags.Tag {
				group.Labels[model.LabelName(invalidLabelCharRE.ReplaceAllString(hostTagsPrefix+t.Name, "_"))] = model.LabelValue("present")
			}
			group.Targets = append(group.Targets, createHostTargets(host, config.TargetPort)...)
			tgs = append(tgs, group)
		}

		// Send updates for hosts that have been removed since the last poll.
		for id := range last {
			if _, ok := present[id]; !ok {
				tgs = append(tgs, &targetgroup.Group{Source: id})
				logger.Log("msg", "host %q removed", id)
			}
		}
		last = present

		return tgs, nil
	}
}

func createHostTargets(h Host, port string) []model.LabelSet {
	lsets := make([]model.LabelSet, 0, len(h.Nics.HostNic))
	for _, nic := range h.Nics.HostNic {
		ls := model.LabelSet{
			model.AddressLabel:                    model.LabelValue(nic.IP.Address + ":" + port),
			model.LabelName(nicBootProtocolLabel): model.LabelValue(nic.BootProtocol),
			model.LabelName(nicBridgedLabel):      model.LabelValue(nic.Bridged),
			model.LabelName(nicGatewayLabel):      model.LabelValue(nic.IP.Gateway),
			model.LabelName(nicNameLabel):         model.LabelValue(nic.Name),
			model.LabelName(nicNetmaskLabel):      model.LabelValue(nic.IP.Netmask),
			model.LabelName(nicMacAddressLabel):   model.LabelValue(nic.Mac.Address),
			model.LabelName(nicStatusLabel):       model.LabelValue(nic.Status),
		}
		lsets = append(lsets, ls)
	}
	return lsets
}
