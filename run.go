package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/wthorp/gosh"
)

type rule struct {
	pattern  regexp.Regexp
	template []byte
}

func initRule(p, t string) rule {
	return rule{pattern: *regexp.MustCompile(p), template: []byte(t)}
}

func main() {
	gosh.Run(`
	// cleanup old runs
	rmdir impacket
	rmdir grumpy

	git clone https://github.com/SecureAuthCorp/impacket.git
	fixPython

	git clone git@github.com:google/grumpy.git

	`, gosh.Calls{"fixPython": fixPython})
}

func fixPython(*gosh.Block, string) error {
	rules := []rule{
		initRule(`//`, `/`),
		initRule(`from __future__ import division`, ``),
		initRule(`from __future__ import print_function`, ``),
	}
	dir, _ := os.Getwd()
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".py") {
			b, err := ioutil.ReadFile(path)
			if err != nil {
				fmt.Print(err)
			}
			for _, r := range rules {
				b = r.pattern.ReplaceAll(b, r.template)
			}
			ioutil.WriteFile(path, b, 0644)
		}
		return nil
	})
	return nil
}
