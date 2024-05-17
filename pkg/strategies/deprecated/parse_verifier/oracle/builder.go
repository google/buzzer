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

package oracle

import (
	"regexp"
	"strconv"
	"strings"
)

func populateOracle(oracle *RegisterOracle, verifierLog string) error {
	// Find lines containing register assignment results. For example:
	//
	// 15: (5f) r7 &= r9                     ; R7_w=scalar(umax=127,var_off=(0x0; 0x7f)) R9=127
	//
	// The following captures the offset (`15`) and assignment (`R9=127`) parts.
	regStateRegex, err := regexp.Compile(`(?P<Offset>\d+):.+; (?P<Assigns>R\d\d?.+)`)
	if err != nil {
		return err
	}

	// This regex then breaks up the captured assignment (`R9=127`) into their
	// register name and value parts.
	scalarRegex, err := regexp.Compile(`R(?P<Reg>\d\d?)(?:_.)?=(?P<Value>-?\d+)`)
	if err != nil {
		return err
	}

	for _, line := range strings.Split(verifierLog, "\n") {
		stateMatch := regStateRegex.FindStringSubmatch(line)
		if stateMatch == nil {
			continue
		}

		offsetStr := stateMatch[1]
		state := stateMatch[2]
		scalarMatch := scalarRegex.FindAllStringSubmatch(state, -1)
		if scalarMatch == nil {
			continue
		}

		offset, err := strconv.Atoi(offsetStr)
		if err != nil {
			return err
		}

		for _, scalar := range scalarMatch {
			regNum, err := strconv.Atoi(scalar[1])
			if err != nil {
				return err
			}
			regValue, err := strconv.Atoi(scalar[2])
			if err != nil {
				return err
			}
			oracle.SetRegValue(int32(offset), uint8(regNum), uint64(regValue))
		}
	}

	return nil
}

// FromVerifierTrace returns a new register oracle built by parsing an eBPF trace log.
func FromVerifierTrace(input string) (*RegisterOracle, error) {
	oracle := NewRegisterOracle()
	err := populateOracle(oracle, input)
	if err != nil {
		return nil, err
	}
	return oracle, nil
}
