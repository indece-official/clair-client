//go:generate /bin/sh -c "mkdir -p generated/model/apiclair && oapi-codegen --package=apiclair --generate=types ../assets/swagger/apiclair.yml > ./generated/model/apiclair/apiclair.gen.go"
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/indece-official/clair-client/src/analyzer"
	"github.com/indece-official/clair-client/src/clair"
	"github.com/indece-official/clair-client/src/docker"
)

// Variables set during build
var (
	ProjectName  string
	BuildVersion string
	BuildDate    string
)

var (
	flagVersion      = flag.Bool("v", false, "Print the version info and exit")
	flagImage        = flag.String("image", "", "Url of docker image")
	flagIndexTimeout = flag.Int("clair-index-timeout", 120, "Index timeout for clair")
	flagQuiet        = flag.Bool("quiet", false, "Be quiet")
)

func main() {
	var err error

	flag.Parse()

	if *flagVersion {
		fmt.Printf("%s %s (Build %s)\n", ProjectName, BuildVersion, BuildDate)
		fmt.Printf("\n")
		fmt.Printf("https://github.com/indece-official/clair-client\n")
		fmt.Printf("\n")
		fmt.Printf("Copyright 2021 by indece UG (haftungsbeschränkt)\n")

		os.Exit(0)

		return
	}

	dockerClient := &docker.DockerClient{}
	clairClient := &clair.ClairClient{}
	aly := &analyzer.Analyzer{}

	err = dockerClient.Connect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to docker: %s\n", err)

		os.Exit(1)

		return
	}

	err = clairClient.Connect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to clair: %s\n", err)

		os.Exit(1)

		return
	}

	err = aly.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing analyzer: %s\n", err)

		os.Exit(1)

		return
	}

	imageIdentifiers, err := docker.ParseImageIdentifiers(*flagImage, dockerClient.GetRegistry())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing docker image name: %s\n", err)

		os.Exit(1)

		return
	}

	if !*flagQuiet {
		fmt.Printf("Logging into docker registry %s ...\n", dockerClient.GetRegistry())
	}

	dockerAuthToken, err := dockerClient.GetAuthToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting docker auth token: %s\n", err)

		os.Exit(1)

		return
	}

	if !*flagQuiet {
		fmt.Printf("Loading docker manifest for image %s:%s from registry ...\n", imageIdentifiers.Repository, imageIdentifiers.Tag)
	}

	manifest, err := dockerClient.GetManifestV2(imageIdentifiers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading docker manifest for image: %s\n", err)

		os.Exit(1)

		return
	}

	hash := string(manifest.Config.Digest)

	startIndexTime := time.Now()
	timeoutIndex := time.Duration(*flagIndexTimeout) * time.Second

	if !*flagQuiet {
		fmt.Printf("Indexing docker manifest in clair ...\n")
	}

	indexStatus, err := clairClient.IndexManifest(
		manifest,
		imageIdentifiers,
		dockerClient.GetRegistry(),
		dockerAuthToken,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error indexing manifest in clair: %s\n", err)

		os.Exit(1)

		return
	}

	if !*flagQuiet {
		fmt.Printf("Waiting for indexing of docker manifest in clair to finish ...\n")
	}

	for time.Since(startIndexTime) < timeoutIndex {
		if indexStatus == clair.IndexStatusFinished {
			break
		}

		time.Sleep(5 * time.Second)

		indexStatus, err = clairClient.GetIndexManifestStatus(hash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting indexing manifest status from clair: %s\n", err)

			os.Exit(1)

			return
		}
	}

	if indexStatus != clair.IndexStatusFinished {
		fmt.Fprintf(os.Stderr, "Error indexing manifest in clair - index status is %s\n", indexStatus)

		os.Exit(1)

		return
	}

	if !*flagQuiet {
		fmt.Printf("Generating vulnerability report ...\n")
	}

	vulnerabilityReport, err := clairClient.GetVulnerabilityReport(hash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading vulnerability report from clair: %s\n", err)

		os.Exit(1)

		return
	}

	if !*flagQuiet {
		fmt.Printf("Processing vulnerability report ...\n")
	}

	analysis, err := aly.Analyze(vulnerabilityReport)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing vulerability report: %s\n", err)

		os.Exit(1)

		return
	}

	aly.PrintResult(analysis, *flagQuiet)

	if !analysis.OK {
		os.Exit(1)

		return
	}
}
