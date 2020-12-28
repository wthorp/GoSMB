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
	rmdir src
	#rmdir grumpy

	mkdir src
	pushd src
	git clone https://github.com/SecureAuthCorp/impacket.git __python__
	cd __python__
	fixPython
	popd
	genmake .
	make

	// you can't seem to 'make' grumpy inside a go module subdir
	#pushd ..
	#git clone git@github.com:google/grumpy.git
	#cd grumpy
	#make
	#export PATH=$PWD/build/bin:$PATH
	#export GOPATH=$PWD/build
	#export PYTHONPATH=$PWD/build/lib/python2.7/site-packages
	#popd


	#grumpc -modname=hello $GOPATH/src/__python__/hello.py > $GOPATH/src/__python__/hello/module.
	

	`, gosh.Calls{"fixPython": fixPython})
}

func fixPython(b *gosh.Block, _ string) error {
	rules := []rule{
		initRule(`//`, `/`),
		initRule(`from __future__ import division`, ``),
		initRule(`from __future__ import print_function`, ``),
		initRule(`from __future__ import unicode_literals`, ``),
		initRule(`from __future__ import absolute_import`, ``),
		initRule(`end=' '\)`, `' ')`),
		initRule(`class (.*)\(\):`, `class $1:`),
	}
	dir := b.Getwd()
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
