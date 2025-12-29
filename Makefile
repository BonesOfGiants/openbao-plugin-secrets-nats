NAME := openbao-plugin-secrets-nats
VERSION := 0.0.0
GOOS := linux
GOARCH := amd64
REGISTRY := ghcr.io/bonesofgiants
OUTPUT_DIR := bin

.PHONY: build
build:
	@GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 \
	go build \
	-o $(OUTPUT_DIR)/$(NAME)-$(GOOS)-$(GOARCH) \
	-ldflags '-s -w -X github.com/bonesofgiants/openbao-plugin-secrets-nats.PluginVersion=$(VERSION)' ./cmd

.PHONY: print-targets
print-targets:
	@bash ./scripts/export-targets.sh $(OUTPUT_DIR) $(NAME)