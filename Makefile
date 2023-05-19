# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

VERSION                     := $(shell cat VERSION)
REGISTRY                    := eu.gcr.io/gardener-project/gardener
NAME                        := egress-filter
IMAGE_REPOSITORY            := $(REGISTRY)/$(NAME)
IMAGE_TAG                   := $(VERSION)
EFFECTIVE_VERSION           := $(VERSION)-$(shell git rev-parse HEAD)
GOARCH                      := amd64
REPO_ROOT                   := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

.PHONY: revendor
revendor:
	@GO111MODULE=on go mod vendor
	@GO111MODULE=on go mod tidy

.PHONY: check
check:
	go fmt ./...
	go vet ./...

.PHONY: test
test:
	go test ./...
	

.PHONY: format
format: install-requirements
	@$(REPO_ROOT)/hack/format.sh ./cmd ./pkg
	
.PHONY: verify
verify: check format test

.PHONY: build
build: build-filter-updater

.PHONY: install-requirements
install-requirements:
	@go install -mod=vendor $(REPO_ROOT)/vendor/golang.org/x/tools/cmd/goimports

.PHONY: build-filter-updater
build-filter-updater:
	@CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) GO111MODULE=on go build -o filter-updater \
        -mod=vendor \
	    -ldflags "-X 'main.Version=$(EFFECTIVE_VERSION)' -X 'main.ImageTag=$(IMAGE_TAG)'"\
	    ./cmd/main.go

.PHONY: docker-images
docker-images:
	@docker build -t $(IMAGE_REPOSITORY):$(IMAGE_TAG) -f Dockerfile --rm .

.PHONY: release
release: docker-images docker-login docker-push

.PHONY: docker-login
docker-login:
	@gcloud auth activate-service-account --key-file .kube-secrets/gcr/gcr-readwrite.json

.PHONY: docker-push
docker-push:
	@if ! docker images $(IMAGE_REPOSITORY) | awk '{ print $$2 }' | grep -q -F $(IMAGE_TAG); then echo "$(IMAGE_REPOSITORY) version $(IMAGE_TAG) is not yet built. Please run 'make docker-images'"; false; fi
	@gcloud docker -- push $(IMAGE_REPOSITORY):$(IMAGE_TAG)
