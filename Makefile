############
# DEFAULTS #
############

KUBECONFIG           ?= ""
GO 					 ?= go
BUILD 				 ?= build
IMAGE_TAG 			 ?= 0.1.0
IMAGE_NAME   		 ?= ""
PLUGIN   		 	 ?= ""

#############
# VARIABLES #
#############

GIT_SHA             := $(shell git rev-parse HEAD)
KOCACHE             ?= /tmp/ko-cache
GOOS                ?= $(shell go env GOOS)
GOARCH              ?= $(shell go env GOARCH)
REGISTRY            ?= ghcr.io
OWNER               ?= kyverno
KO_REGISTRY         := ko.local
LD_FLAGS            := "-s -w"
LOCAL_PLATFORM      := linux/$(GOARCH)
PLATFORMS           := all
REPO                := $(REGISTRY)/$(OWNER)/$(IMAGE_NAME)
KO_TAGS             := $(shell git rev-parse --short HEAD)

ifndef VERSION
KO_TAGS         := $(shell git rev-parse --short HEAD)
else
KO_TAGS         := $(VERSION)
endif


#########
# TOOLS #
#########
TOOLS_DIR      					   := $(PWD)/.tools
KO             					   := $(TOOLS_DIR)/ko
KO_VERSION     				       := v0.18.0
GCI                                := $(TOOLS_DIR)/gci
GCI_VERSION                        := v0.13.7
GOFUMPT                            := $(TOOLS_DIR)/gofumpt
GOFUMPT_VERSION                    := v0.9.1
HELM                               := $(TOOLS_DIR)/helm
HELM_VERSION                       := v3.19.1
HELM_DOCS                          := $(TOOLS_DIR)/helm-docs
HELM_DOCS_VERSION                  := v1.14.2

$(HELM):
	@echo Install helm... >&2
	@GOBIN=$(TOOLS_DIR) go install helm.sh/helm/v3/cmd/helm@$(HELM_VERSION)

$(HELM_DOCS):
	@echo Install helm-docs... >&2
	@GOBIN=$(TOOLS_DIR) go install github.com/norwoodj/helm-docs/cmd/helm-docs@$(HELM_DOCS_VERSION)

$(KO):
	@echo Install ko... >&2
	@GOBIN=$(TOOLS_DIR) go install github.com/google/ko@$(KO_VERSION)

$(GCI):
	@echo Install gci... >&2
	@GOBIN=$(TOOLS_DIR) go install github.com/daixiang0/gci@$(GCI_VERSION)

$(GOFUMPT):
	@echo Install gofumpt... >&2
	@GOBIN=$(TOOLS_DIR) go install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)


.PHONY: gci
gci: $(GCI)
	@echo "Running gci"
	@$(GCI) write -s standard -s default -s "prefix(github.com/kyverno/policy-reporter/kyverno-plugin/)" ./plugins/kyverno
	@$(GCI) write -s standard -s default -s "prefix(github.com/kyverno/policy-reporter/trivy-plugin/)" ./plugins/trivy
	@$(GCI) write -s standard -s default -s "prefix(github.com/kyverno/policy-reporter/vap-plugin/)" ./plugins/vap

.PHONY: gofumpt
gofumpt: $(GOFUMPT)
	@echo "Running gofumpt"
	@$(GOFUMPT) -w ./plugins/$(PLUGIN)

.PHONY: fmt
fmt: gci gofumpt

.PHONY: install-tools
install-tools: $(TOOLS) ## Install tools

.PHONY: clean-tools
clean-tools: ## Remove installed tools
	@echo Clean tools... >&2
	@rm -rf $(TOOLS_DIR)

###################
# BUIDL / PUBLISH #
###################

.PHONY: ko-build
ko-build: $(KO)
	@echo Build image with ko... >&2
	@cd plugins/$(PLUGIN) && LDFLAGS='$(LD_FLAGS)' KOCACHE=$(KOCACHE) KO_DOCKER_REPO=$(KO_REGISTRY) \
		$(KO) build . --tags=$(KO_TAGS) --platform=$(LOCAL_PLATFORM)

.PHONY: ko-login
ko-login: $(KO)
	@$(KO) login $(REGISTRY) --username "$(REGISTRY_USERNAME)" --password "$(REGISTRY_PASSWORD)"

.PHONY: ko-publish
ko-publish: ko-login
	@echo Publishing image "$(KO_TAGS)" with ko... >&2
	@cd plugins/$(PLUGIN) && LDFLAGS='$(LD_FLAGS)' KOCACHE=$(KOCACHE) KO_DOCKER_REPO=$(REPO) \
		$(KO) build . --bare --tags=$(KO_TAGS) --push --platform=$(PLATFORMS)