package mactable

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/lwlcom/cisco_exporter/rpc"
)

func (c *mactableCollector) Parse(ostype string, output string) (int, error) {
	if ostype != rpc.NXOS {
		return 0, errors.New("mactable is not implemented yet for " + ostype)
	}

	macRegexp := regexp.MustCompile(`in Use:\s+(\d+)$`)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if matches := macRegexp.FindStringSubmatch(line); matches != nil {
			count, err := strconv.Atoi(matches[1])
			if err != nil {
				return 0, err
			}
			return count, nil
		}
	}

	return 0, errors.New("count not found")
}

func (c *mactableCollector) ParseVlans(ostype string, output string) ([]int, error) {
	if ostype != rpc.NXOS {
		return nil, errors.New("mactable is not implemented yet for " + ostype)
	}
	
	vlans := make([]int, 0)
	vlanRegexp := regexp.MustCompile(`^\s*(\d+)\s+`)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if matches := vlanRegexp.FindStringSubmatch(line); matches != nil {
			vlan, err := strconv.Atoi(matches[1])
			if err != nil {
				return nil, err
			}
			vlans = append(vlans, vlan)
		}
	}
	return vlans, nil
}