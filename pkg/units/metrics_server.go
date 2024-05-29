// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package units

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/safehtml"
)

// MetricsServer exposes an http server where information about coverage/metrics
// can be visualized.
type MetricsServer struct {
	host              string
	port              uint16
	metricsCollection *MetricsCollection
	filePath          string
}

type lineInfo struct {
	LineNumber int
	LineData   string
	IsCovered  bool
}

type fileCoverageInfo struct {
	FileName     string
	FullPath     string
	CoveredLines int
	FileExists   bool
	Coverage     []lineInfo
}

func (ms *MetricsServer) handleLatestLog(w http.ResponseWriter, req *http.Request) {
	log := ms.metricsCollection.getLatestLog()
	fmt.Fprintf(w, "<html>\n<table>\n<tr>\n<td>\n")
	logLines := strings.Split(log, "\n")
	for _, line := range logLines {
		fmt.Fprintf(w, "%s<br>", line)
	}
	fmt.Fprintf(w, "</td>\n</tr>\n</table>\n</html>\n")
}

func (ms *MetricsServer) handleVerifierErrors(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "<html>\n<table>\n")
	verdicts := ms.metricsCollection.getVerifierVerdicts()
	keys := make([]string, 0, len(verdicts))
	for key := range verdicts {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return verdicts[keys[i]] > verdicts[keys[j]]
	})
	fmt.Fprintf(w, "<tr>\n")
	fmt.Fprintf(w, "<td> <b>Verdict</b> </td>\n")
	fmt.Fprintf(w, "<td> <b>Count</b> </td>\n")
	fmt.Fprintf(w, "</tr>\n")
	for _, k := range keys {
		fmt.Fprintf(w, "<tr>\n")
		fmt.Fprintf(w, "<td> %s </td>\n", k)
		fmt.Fprintf(w, "<td> %d </td>\n", verdicts[k])
		fmt.Fprintf(w, "</tr>\n")
	}
	fmt.Fprintf(w, "</table>\n</html>\n")
}

func (ms *MetricsServer) handleFileCoverage(w http.ResponseWriter, req *http.Request) {
	fileParam, ok := req.URL.Query()["file"]
	if !ok {
		fmt.Fprintf(w, "Should specify file to check for coverage")
		return
	}
	if len(fileParam) == 0 {
		fmt.Fprintf(w, "FileParam is empty")
		return
	}

	fs := os.DirFS(ms.filePath)
	file := fileParam[0]

	_, _, coverageInformation := ms.metricsCollection.getMetrics()
	var covInfo *CoverageInfo
	for _, cov := range coverageInformation {
		if cov.fileName == file {
			covInfo = &cov
			break
		}
	}

	if covInfo == nil {
		fmt.Fprintf(w, "No coverage info for file %s\n", file)
		return
	}
	coveredLines := make(map[int]bool)
	for _, line := range covInfo.coveredLines {
		coveredLines[line] = true
	}
	readFile, err := fs.Open(file)
	if err != nil {
		fmt.Fprintf(w, "Could not open file %s for reading\n", file)
		return
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	fc := &fileCoverageInfo{
		FileName: file,
		Coverage: []lineInfo{},
	}
	i := 0
	for fileScanner.Scan() {
		i++
		li := lineInfo{
			LineNumber: i,
		}
		_, li.IsCovered = coveredLines[i]
		li.LineData = fileScanner.Text()
		fc.Coverage = append(fc.Coverage, li)
	}

	fmt.Fprintf(w, "<html>\n")
	fmt.Fprintf(w, "<table>\n")
	for _, coverage := range fc.Coverage {
		fmt.Fprintf(w, "<tr>\n")
		fmt.Fprintf(w, "<td>\n")
		lineNumberString := safehtml.HTMLEscaped(fmt.Sprintf("%d", coverage.LineNumber))
		fmt.Fprintf(w, "%s", lineNumberString)
		fmt.Fprintf(w, "</td>\n")
		if coverage.IsCovered {
			fmt.Fprintf(w, "<td style='background-color:#7dff83;'>\n")
		} else {
			fmt.Fprintf(w, "<td>\n")
		}
		safeContent := safehtml.HTMLEscaped(coverage.LineData)
		fmt.Fprintf(w, "<pre>%s</pre>\n", safeContent)
		fmt.Fprintf(w, "</td>\n")
		fmt.Fprintf(w, "</tr>\n")
	}
	fmt.Fprintf(w, "</table>\n")
	fmt.Fprintf(w, "</html>\n")
}

type generalInfo struct {
	ProgramsVerified int
	ValidPrograms    int
	EfficacyRatio    float64
	CoveredFiles     []*fileCoverageInfo
}

func (ms *MetricsServer) handleIndex(w http.ResponseWriter, req *http.Request) {
	programsVerified, validPrograms, coverageInformation := ms.metricsCollection.getMetrics()
	gi := &generalInfo{
		ProgramsVerified: programsVerified,
		ValidPrograms:    validPrograms,
		EfficacyRatio:    (float64(validPrograms) / float64(programsVerified)) * 100,
		CoveredFiles:     []*fileCoverageInfo{},
	}

	for _, covInfo := range coverageInformation {
		fc := &fileCoverageInfo{
			FileName:     covInfo.fileName,
			FullPath:     covInfo.fullPath,
			CoveredLines: len(covInfo.coveredLines),
		}
		_, err := os.Stat(filepath.Join(ms.filePath, covInfo.fileName))
		fc.FileExists = !errors.Is(err, os.ErrNotExist)
		gi.CoveredFiles = append(gi.CoveredFiles, fc)
	}

	sort.Slice(gi.CoveredFiles, func(i, j int) bool {
		return gi.CoveredFiles[i].CoveredLines > gi.CoveredFiles[j].CoveredLines
	})

	fmt.Fprintf(w, "<html>\n")
	statsLine := safehtml.HTMLEscaped(fmt.Sprintf("%d have been verified, %d were valid (%f percent were valid)", gi.ProgramsVerified, gi.ValidPrograms, gi.EfficacyRatio)).String()
	fmt.Fprintf(w, "<h2>%s</h2>\n", statsLine)
	fmt.Fprintf(w, "<ul>\n")
	for _, coveredFile := range gi.CoveredFiles {
		fmt.Fprintf(w, "<li>\n")
		var safeFileName string
		if coveredFile.FileExists {
			safeURL := safehtml.HTMLEscaped(fmt.Sprintf("fileCoverage?file=%s", coveredFile.FileName)).String()
			safeFileName = safehtml.HTMLEscaped(coveredFile.FileName).String()
			fmt.Fprintf(w, "<a href='%s'> %s </a>", safeURL, safeFileName)
		} else {
			safeFileName = safehtml.HTMLEscaped(coveredFile.FileName).String()
			fmt.Fprintf(w, "%s", safeFileName)
		}
		fmt.Fprintf(w, "<ul>\n")

		fullPathString := safehtml.HTMLEscaped(fmt.Sprintf("%s", coveredFile.FullPath)).String()
		fmt.Fprintf(w, "<li>full path: %s</li>\n", fullPathString)

		coveredLinesString := safehtml.HTMLEscaped(fmt.Sprintf("%d", coveredFile.CoveredLines)).String()
		fmt.Fprintf(w, "<li>covered lines: %s</li>\n", coveredLinesString)
		fmt.Fprintf(w, "</ul>\n")

		fmt.Fprintf(w, "</li>\n")
	}
	fmt.Fprintf(w, "</ul>\n")
	fmt.Fprintf(w, "</html>\n")
}

func (ms *MetricsServer) serve() {
	http.HandleFunc("/", ms.handleIndex)
	http.HandleFunc("/fileCoverage", ms.handleFileCoverage)
	http.HandleFunc("/latestLog", ms.handleLatestLog)
	http.HandleFunc("/verifierErrors", ms.handleVerifierErrors)
	http.ListenAndServe(fmt.Sprintf("%s:%d", ms.host, ms.port), nil)
}
