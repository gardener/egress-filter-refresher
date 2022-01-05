# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

VERSION                     := $(shell cat VERSION)
REGISTRY                    := eu.gcr.io/gardener-project/gardener
PREFIX                      := egress-filter
UPDATER_IMAGE_REPOSITORY    := $(REGISTRY)/$(PREFIX)-refresher
UPDATER_IMAGE_TAG           := $(VERSION)
BLACKHOLER_IMAGE_REPOSITORY := $(REGISTRY)/$(PREFIX)-blackholer
BLACKHOLER_IMAGE_TAG        := $(VERSION)
FIREWALLER_IMAGE_REPOSITORY := $(REGISTRY)/$(PREFIX)-firewaller
FIREWALLER_IMAGE_TAG        := $(VERSION)

PATH              := $(GOBIN):$(PATH)

export PATH

.PHONY: docker-images
docker-images:
	@docker build -t $(UPDATER_IMAGE_REPOSITORY):$(UPDATER_IMAGE_TAG) -f updater/Dockerfile --rm .
	@docker build -t $(BLACKHOLER_IMAGE_REPOSITORY):$(BLACKHOLER_IMAGE_TAG) -f blackholer/Dockerfile --rm .
	@docker build -t $(FIREWALLER_IMAGE_REPOSITORY):$(FIREWALLER_IMAGE_TAG) -f firewaller/Dockerfile --rm .

.PHONY: release
release: docker-images docker-login docker-push

.PHONY: docker-login
docker-login:
	@gcloud auth activate-service-account --key-file .kube-secrets/gcr/gcr-readwrite.json

.PHONY: docker-push
docker-push:
	@if ! docker images $(UPDATER_IMAGE_REPOSITORY) | awk '{ print $$2 }' | grep -q -F $(UPDATER_IMAGE_TAG); then echo "$(UPDATER_IMAGE_REPOSITORY) version $(UPDATER_IMAGE_TAG) is not yet built. Please run 'make docker-images'"; false; fi
	@gcloud docker -- push $(UPDATER_IMAGE_REPOSITORY):$(UPDATER_IMAGE_TAG)
	@if ! docker images $(BLACKHOLER_IMAGE_REPOSITORY) | awk '{ print $$2 }' | grep -q -F $(BLACKHOLER_IMAGE_TAG); then echo "$(BLACKHOLER_IMAGE_REPOSITORY) version $(BLACKHOLER_IMAGE_TAG) is not yet built. Please run 'make docker-images'"; false; fi
	@gcloud docker -- push $(BLACKHOLER_IMAGE_REPOSITORY):$(BLACKHOLER_IMAGE_TAG)
	@if ! docker images $(FIREWALLER_IMAGE_REPOSITORY) | awk '{ print $$2 }' | grep -q -F $(FIREWALLER_IMAGE_TAG); then echo "$(FIREWALLER_IMAGE_REPOSITORY) version $(FIREWALLER_IMAGE_TAG) is not yet built. Please run 'make docker-images'"; false; fi
	@gcloud docker -- push $(FIREWALLER_IMAGE_REPOSITORY):$(FIREWALLER_IMAGE_TAG)
