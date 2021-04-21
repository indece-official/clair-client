package analyzer

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/indece-official/clair-client/src/generated/model/apiclair"
	"github.com/jedib0t/go-pretty/v6/table"
)

var (
	flagWhitelist   = flag.String("whitelist", "", "Name of whitelist file for CVEs")
	flagMaxSeverity = flag.String("max-severity", "Medium", "Maximum severity regarded as ok")
)

var SeverityRanking = map[string]int{
	"Unknown":    0,
	"Negligible": 1,
	"Low":        2,
	"Medium":     3,
	"High":       4,
	"Critical":   5,
}

type AnalyzerResultRow struct {
	VulnerabilityName  string
	Severity           string
	ComponentNamespace string
	ComponentName      string
	Version            string
	FixedIn            string
	Whitelisted        bool
}

type AnalyzerResult struct {
	OK                       bool
	Rows                     []*AnalyzerResultRow
	CountTotal               int
	CountNotOKWhitelisted    int
	CountNotOKNotWhitelisted int
}

type Analyzer struct {
	whitelist       map[string]bool
	maxSeverityRank int
}

func (a *Analyzer) Load() error {
	var ok bool
	a.maxSeverityRank, ok = SeverityRanking[*flagMaxSeverity]
	if !ok {
		return fmt.Errorf("invalid maximum severity")
	}

	a.whitelist = map[string]bool{}

	if *flagWhitelist != "" {
		whitelistData, err := ioutil.ReadFile(*flagWhitelist)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}

			return fmt.Errorf("error loading whitelist: %s", err)
		}

		whitelistRows := strings.Split(string(whitelistData), "\n")
		for _, whitelistRow := range whitelistRows {
			whitelistRow = strings.Trim(whitelistRow, " \t")
			if whitelistRow == "" ||
				strings.HasPrefix(whitelistRow, "#") {
				continue
			}

			whitelistRow = strings.ToUpper(whitelistRow)

			a.whitelist[whitelistRow] = true
		}
	}

	return nil
}

func (a *Analyzer) Analyze(vulnerabilityReport *apiclair.VulnerabilityReport) (*AnalyzerResult, error) {
	result := &AnalyzerResult{}
	result.Rows = []*AnalyzerResultRow{}

	for _, vulnerability := range vulnerabilityReport.Vulnerabilities.AdditionalProperties {
		row := &AnalyzerResultRow{}

		row.VulnerabilityName = vulnerability.Name
		row.Severity = vulnerability.NormalizedSeverity

		version := ""

		if vulnerability.Distribution != nil {
			row.ComponentNamespace = vulnerability.Distribution.PrettyName
			if vulnerability.Distribution.Version != "" {
				version = vulnerability.Distribution.Version
			}
		} else {
			row.ComponentNamespace = ""
		}

		if vulnerability.Range != nil && *vulnerability.Range != "" {
			version = *vulnerability.Range
		}

		if vulnerability.Package != nil {
			row.ComponentName = vulnerability.Package.Name
			if vulnerability.Package.Version != "" {
				version = vulnerability.Package.Version
			}
		} else {
			row.ComponentName = ""
		}

		row.Version = version
		row.FixedIn = vulnerability.FixedInVersion

		whitelisted := false
		if ok, exists := a.whitelist[strings.ToUpper(vulnerability.Name)]; ok && exists {
			whitelisted = true
		}

		row.Whitelisted = whitelisted

		severityRank, ok := SeverityRanking[vulnerability.NormalizedSeverity]
		if !ok {
			severityRank = 0
		}

		result.CountTotal++

		if severityRank > a.maxSeverityRank {
			if whitelisted {
				result.CountNotOKWhitelisted++
			} else {
				result.CountNotOKNotWhitelisted++
			}
		}

		result.Rows = append(result.Rows, row)
	}

	result.OK = result.CountNotOKNotWhitelisted == 0

	return result, nil
}

func (a *Analyzer) PrintResult(result *AnalyzerResult, quiet bool) {
	if !quiet {
		fmt.Printf("\n")

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{
			"Vulnerability",
			"Severity",
			"Component",
			"Version",
			"FixedIn",
			"Whitelisted",
		})
		for _, resultRow := range result.Rows {
			componentName := ""
			if resultRow.ComponentNamespace != "" && resultRow.ComponentName != "" {
				componentName = fmt.Sprintf("%s > %s", resultRow.ComponentNamespace, resultRow.ComponentName)
			} else if resultRow.ComponentNamespace != "" {
				componentName = resultRow.ComponentNamespace
			} else if resultRow.ComponentName != "" {
				componentName = resultRow.ComponentName
			}

			t.AppendRow(table.Row{
				resultRow.VulnerabilityName,
				resultRow.Severity,
				componentName,
				resultRow.Version,
				resultRow.FixedIn,
				resultRow.Whitelisted,
			})
		}
		t.Render()
	}

	f := os.Stdout
	if !result.OK {
		f = os.Stderr
	}

	if !quiet || !result.OK {
		fmt.Fprintf(
			f,
			"\nFound %d vulnerabilities with severity '%s' or more (%d whitelisted)\n\n",
			result.CountNotOKNotWhitelisted+result.CountNotOKWhitelisted,
			*flagMaxSeverity,
			result.CountNotOKWhitelisted,
		)
	}
}
