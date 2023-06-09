# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v
# This should be disabled if the binary uses pprof
LDFLAGS := -s -w

ifneq ($(shell go env GOOS),darwin)
LDFLAGS := -extldflags "-static"
endif
    
all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "gosecurity" cmd/gosecurity/main.go
docs:
	if ! which dstdocgen > /dev/null; then
		echo -e "Command not found! Install? (y/n) \c"
		go get -v github.com/gosecurity/yamldoc-go/cmd/docgen/dstdocgen
	fi
	$(GOCMD) generate pkg/templates/templates.go
	$(GOBUILD) -o "cmd/docgen/docgen" cmd/docgen/docgen.go
	./cmd/docgen/docgen docs.md gosecurity-jsonschema.json
test:
	$(GOTEST) $(GOFLAGS) ./...
integration:
	cd ../integration_tests; bash run.sh
functional:
	cd cmd/functional-test; bash run.sh
tidy:
	$(GOMOD) tidy
