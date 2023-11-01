package units

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type CoverageInfo struct {
	fileName     string
	fullPath     string
	coveredLines []int
}

// CoverageManager deals with everything coverage related.
type CoverageManager struct {
	coverageLock sync.Mutex

	coverageCache   map[uint64]string
	coverageInfoMap map[string]*CoverageInfo

	addressToLineFunction func(string) (string, error)
}

// ProcessCoverageAddresses converts raw coverage hex addresses into line
// numbers and files, it also caches the results.
func (cm *CoverageManager) ProcessCoverageAddresses(cov []uint64) error {
	cm.coverageLock.Lock()
	defer cm.coverageLock.Unlock()

	unknownAddr := []uint64{}
	for _, address := range cov {
		if _, ok := cm.coverageCache[address]; !ok {
			unknownAddr = append(unknownAddr, address)
		}
	}

	if len(unknownAddr) == 0 {
		return nil
	}

	inputString := ""
	for _, ukAddr := range unknownAddr {
		inputString += fmt.Sprintf("%02x\n", ukAddr)
	}

	outString, err := cm.addressToLineFunction(inputString)
	if err != nil {
		fmt.Printf("addressToLine error: %v\n", err)
		return err
	}

	coverage := strings.Split(outString, "\n")
	for i, line := range coverage {
		if len(line) == 0 {
			continue
		}
		lineSplit := strings.Split(line, " ")
		if len(lineSplit) == 0 {
			continue
		}
		cleanedLine := lineSplit[0]
		pathSplit := strings.Split(cleanedLine, "/")
		if len(pathSplit) == 0 {
			continue
		}
		fnAndLn := strings.Split(pathSplit[len(pathSplit)-1], ":")
		if len(fnAndLn) == 0 {
			continue
		}
		fileName := fnAndLn[0]
		lineNumber, err := strconv.Atoi(fnAndLn[1])
		if err != nil {
			return err
		}
		fullPath := strings.Split(cleanedLine, ":")[0]

		cm.coverageCache[unknownAddr[i]] = fnAndLn[0] + ":" + fnAndLn[1]
		cm.recordCoverageLine(fileName, fullPath, lineNumber)
	}
	return nil
}

// RecordCoverageLine records a new observed coverage line and adds it to the
// corresponding file cache.
func (cm *CoverageManager) recordCoverageLine(fileName, fullPath string, lineNumber int) {
	if info, ok := cm.coverageInfoMap[fileName]; !ok {
		cm.coverageInfoMap[fileName] = &CoverageInfo{
			fileName:     fileName,
			fullPath:     fullPath,
			coveredLines: []int{lineNumber},
		}
	} else {
		info.coveredLines = append(info.coveredLines, lineNumber)
	}
}

// GetCoverageInfoMap returns the coverage info cache.
func (cm *CoverageManager) GetCoverageInfoMap() *map[string]*CoverageInfo {
	return &cm.coverageInfoMap
}
