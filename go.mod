module github.com/rmohr/ovirt-prometheus-bridge

require (
	github.com/go-kit/kit v0.8.0
	github.com/pkg/errors v0.8.1
	github.com/prometheus/common v0.4.1
	github.com/prometheus/prometheus v0.0.0-20190525122359-d20e84d0fb64
)

replace github.com/prometheus/prometheus => github.com/simonpasquier/prometheus v0.0.0-20190614121925-809ff0167e8c
