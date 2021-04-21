# Project config
PROJECT_NAME=clair-client
BUILD_DATE=$(shell date +%Y%m%d.%H%M%S)
BUILD_VERSION ?= $(shell git rev-parse --short HEAD)-SNAPSHOT

# Go parameters
GOCMD=go
GOPATH=$(shell $(GOCMD) env GOPATH))
GOBUILD=$(GOCMD) build
GOGENERATE=$(GOCMD) generate
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
DIR_SOURCE=./src
DIR_DIST=./dist
DIR_GENERATED_MODEL=$(DIR_SOURCE)/generated/model
BINARY_NAME_LINUX64=$(PROJECT_NAME)-$(BUILD_VERSION)-linux-amd64
SHA256_NAME_LINUX64=$(PROJECT_NAME)-$(BUILD_VERSION)-linux-amd64.sha256
LDFLAGS := 
LDFLAGS := $(LDFLAGS) -X main.ProjectName=$(PROJECT_NAME)
LDFLAGS := $(LDFLAGS) -X main.BuildDate=$(BUILD_DATE)
LDFLAGS := $(LDFLAGS) -X main.BuildVersion=$(BUILD_VERSION)


all: generate test build

generate:
	mkdir -p $(DIR_GENERATED_MODEL)
	rm -rf $(DIR_GENERATED_MODEL)/*
	$(GOGENERATE) -tags=bindata ./...

build:
	mkdir -p $(DIR_DIST)/bin
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(DIR_DIST)/bin/$(BINARY_NAME_LINUX64) -tags=prod -v $(DIR_SOURCE)/main.go
	(cd $(DIR_DIST)/bin && sha256sum $(BINARY_NAME_LINUX64) > $(SHA256_NAME_LINUX64))

test:
	mkdir -p $(DIR_DIST)
ifeq ($(OUTPUT),json)
	$(GOTEST) -v ./...  -cover -coverprofile $(DIR_DIST)/cover.out -json > $(DIR_DIST)/test.json
else
	$(GOTEST) -v ./...  -cover
endif

clean:
	rm -rf $(DIR_OUT)

run:
	$(GOBUILD) -o $(BINARY_NAME) -v ./...
	./$(BINARY_NAME)

deps:
	echo test
