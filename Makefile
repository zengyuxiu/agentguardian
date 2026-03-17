CLANG ?= clang
CFLAGS := -O2 -g -Wall
GO_BUILD := go build -buildvcs=false

build: generate
	cd cmd/agentguardian && \
	$(GO_BUILD) -o ../../bin/agentguardian .

test:
	go test ./...

integration-test:
	go test -tags=integration ./cmd/agentguardian -v

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...
