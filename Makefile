NAME := openbao-plugin-secrets-nats
IMAGE_NAME := ghcr.io/bonesofgiants/openbao-plugin-secrets-nats
VERSION := v0.0.0
GOOS := linux
GOARCH := amd64
REGISTRY := ghcr.io/bonesofgiants
OUTPUT_DIR := bin
RELEASE_DIR := release
GITHUB_REPOSITORY := BonesOfGiants/openbao-plugin-secrets-nats

.PHONY: build
build:
	@GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 \
		go build \
		-o $(OUTPUT_DIR)/$(NAME)-$(GOOS)-$(GOARCH) \
		-ldflags '-s -w -X github.com/bonesofgiants/openbao-plugin-secrets-nats.PluginVersion=$(VERSION)' ./cmd
	
.PHONY: package
package:
	@mkdir -p $(RELEASE_DIR)
	@for f in $(OUTPUT_DIR)/*; do \
		(cd $(OUTPUT_DIR); sha256sum "$$(basename $$f)" > "../$(RELEASE_DIR)/$$(basename $$f).sha256"); \
		tar -czf $(RELEASE_DIR)/$$(basename $$f).tar.gz -C $(OUTPUT_DIR) $$(basename $$f); \
	done

.PHONY: wiki
wiki:
	@rm -rf .wiki
	@mkdir -p .wiki
	@git clone https://github.com/$(GITHUB_REPOSITORY).wiki.git .wiki
	@(cd wiki && git remote set-url origin https://x-access-token:$(GITHUB_TOKEN)@github.com/$(GITHUB_REPOSITORY).wiki.git)

	@sed \
	  -Ee 's#\(\./index\.md(\#[^)]+)?\)#(wiki\1)#g' \
	  -Ee 's#\(\./api\.md(\#[^)]+)?\)#(wiki/API\1)#g' \
	  docs/index.md > .wiki/Home.md

	@sed \
	  -Ee 's#\(\./index\.md(\#[^)]+)?\)#(wiki\1)#g' \
	  -Ee 's#\(\./api\.md(\#[^)]+)?\)#(wiki/API\1)#g' \
	  docs/api.md > .wiki/API.md

.PHONY: update-readme
update-readme:
	@IMAGE_NAME="$(IMAGE_NAME)" TAG="$(VERSION)" BINARY_NAME="$(NAME)" bash ./scripts/update-readme.sh

.PHONY: print-sha256
print-sha256:
	@sha=""; \
	for f in $(RELEASE_DIR)/*.sha256; do \
		export sha="$${sha}$$(cat $$f)\n"; \
	done; \
	echo $$sha

.PHONY: print-targets
print-targets:
	@bash ./scripts/export-targets.sh $(OUTPUT_DIR) $(NAME)
