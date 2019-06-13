package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

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
	Status         string
	Type           string
	Version        Version
}

type Version struct {
	FullVersion string `json:"full_version,omitempty"`
}

type Cluster struct {
	ID string
}

type Config struct {
	Target         string
	URL            string
	User           string
	Password       string
	NoVerify       bool
	EngineCA       string
	UpdateInterval time.Duration
	TargetPort     string
}

func main() {
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
	config := Config{Target: *target,
		URL:            *engineURL,
		User:           *engineUser,
		Password:       *enginePassword,
		NoVerify:       *noVerify,
		EngineCA:       *engineCa,
		UpdateInterval: time.Duration(*updateInterval) * time.Second,
		TargetPort:     strconv.Itoa(*targetPort),
	}

	if !strings.HasPrefix(config.URL, "https") {
		log.Fatal("Only URLs starting with 'https' are supported")
	}
	if config.Password == "" {
		log.Fatal("No engine password supplied")
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.NoVerify,
	}
	if !config.NoVerify {
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(readFile(config.EngineCA))
		if !ok {
			log.Panic("Could not load root CA certificate")
		}

		tlsConfig.RootCAs = roots
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	discoverer := refresh.NewDiscovery(
		nil,
		"ovirt",
		time.Duration(config.UpdateInterval),
		refresher(client, &config),
	)

	ctx := context.Background()
	sdAdapter := adapter.NewAdapter(ctx, *target, "ovirt", discoverer, nil)
	sdAdapter.Run()

	<-ctx.Done()
}

var (
	oVirtPrefix = model.MetaLabelPrefix + "ovirt_"

	clusterPrefix  = oVirtPrefix + "cluster_"
	clusterIDLabel = clusterPrefix + "id"

	hostPrefix              = oVirtPrefix + "host_"
	hostIDLabel             = hostPrefix + "id"
	hostNameLabel           = hostPrefix + "name"
	hostExternalStatusLabel = hostPrefix + "external_status"
	hostStatusLabel         = hostPrefix + "status"
	hostVersionLabel        = hostPrefix + "version"
	hostLibvirtLabel        = hostPrefix + "libvirt_version"
	hostTypeLabel           = hostPrefix + "type"
)

func refresher(client *http.Client, config *Config) func(ctx context.Context) ([]*targetgroup.Group, error) {
	last := make(map[string]struct{})

	return func(ctx context.Context) ([]*targetgroup.Group, error) {
		req, err := http.NewRequest("GET", config.URL+"/ovirt-engine/api/hosts", nil)
		check(err)
		req.Header.Add("Accept", "application/json")
		req.SetBasicAuth(config.User, config.Password)

		res, err := client.Do(req)
		if err != nil {
			log.Print(err)
			return nil, err
		}

		b, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			log.Print(err)
			return nil, err
		}

		var hosts Hosts
		err = json.Unmarshal(b, &hosts)
		if err != nil {
			log.Print(err)
			return nil, err
		}

		tgs := make([]*targetgroup.Group, 0, len(hosts.Host))
		present := make(map[string]struct{})
		for _, host := range hosts.Host {
			tgs = append(tgs, createHostTarget(host, config.TargetPort))
			present[host.ID] = struct{}{}
			last[host.ID] = struct{}{}
		}

		// Send updates for hosts that have been removed since the last poll.
		for id := range last {
			if _, ok := present[id]; !ok {
				tgs = append(tgs, &targetgroup.Group{Source: id})
				log.Printf("host %q removed", id)
			}
		}
		last = present

		return tgs, nil
	}
}

func createHostTarget(h Host, port string) *targetgroup.Group {
	return &targetgroup.Group{
		Targets: []model.LabelSet{
			model.LabelSet{
				model.AddressLabel: model.LabelValue(h.Address + ":" + port),
			}},
		Labels: model.LabelSet{
			model.LabelName(clusterIDLabel): model.LabelValue(h.Cluster.ID),

			model.LabelName(hostIDLabel):             model.LabelValue(h.ID),
			model.LabelName(hostNameLabel):           model.LabelValue(h.Name),
			model.LabelName(hostExternalStatusLabel): model.LabelValue(h.ExternalStatus),
			model.LabelName(hostStatusLabel):         model.LabelValue(h.Status),
			model.LabelName(hostVersionLabel):        model.LabelValue(h.Version.FullVersion),
			model.LabelName(hostLibvirtLabel):        model.LabelValue(h.Libvirt.FullVersion),
			model.LabelName(hostTypeLabel):           model.LabelValue(h.Type),
		},
		Source: h.ID,
	}
}

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func readFile(fileName string) []byte {
	bytes, err := ioutil.ReadFile(fileName)
	check(err)
	return bytes
}
