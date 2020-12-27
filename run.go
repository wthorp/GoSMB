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

func hackPythonToGo() {
	rules := []rule{
		initRule(`(\s*)#(.*)`, `$1//$2`),                                 //comments
		initRule(`(\s*)([_A-Za-z]+)(\s*)=(\s*)(x\d+)`, `$1$2$3=$4$5`),    //vars
		initRule(`(\s*)class (.*)\((.*)\)`, `$1 type $2 struct { // $3`), //classes
		initRule(`(\s*)class (.*)`, `$1 type $2 struct {`),               //classes
		initRule(`(\s*)structure =`, ``),                                 //classes
		initRule(`(\n)(\s*)\)`, `$1$2}`),                                 // classes

		initRule(`(\s*)def (.*)\(\):`, `$1 func $2(){`),                                     //funcs
		initRule(`(\s*)def (.*)\(self\):`, `$1 func (self TYPE) $2(){`),                     //funcs
		initRule(`(\s*)def (.*)\(self, (.*)\):`, `$1 func (self TYPE) $2($3 interface{}){`), //funcs
		initRule(`(\s*)def (.*)\((.*)\):`, `$1 func $2($3 interface{}){`),                   //funcs
		initRule(`\['([^']*)'\]`, `["$1"]`),                                                 //strings
		initRule(`\('([^']*)'\)`, `("$1")`),                                                 //strings
		initRule(` = '([^']*)'`, ` = "$1"`),                                                 //strings
		initRule(`if (.*):`, `if $1 {`),                                                     //if
		initRule(`else(.*):`, `} else $1 {`),                                                //else
		initRule(`elif (.*):`, `} else if $1 {`),                                            //else if
		initRule(`True`, `true`),                                                            //true
		initRule(`False`, `false`),                                                          //false
		initRule(`is None`, `== nil`),                                                       //none
		initRule(`None`, `nil`),                                                             //none
		initRule(`self\["(.+)"\]`, `self.$1`),                                               // field accessor

		initRule(`(\s*)\('(.*)',\s*'<B(.*)'\),`, "$1 $2 byte // $3"),         //fields
		initRule(`(\s*)\('(.*)',\s*'<h(.*)'\),`, "$1 $2 int16 // $3"),        //fields
		initRule(`(\s*)\('(.*)',\s*'<H(.*)'\),`, "$1 $2 uint16 // $3"),       //fields
		initRule(`(\s*)\('(.*)',\s*'<I(.*)'\),`, "$1 $2 uint32 // $3"),       //fields
		initRule(`(\s*)\('(.*)',\s*'<L(.*)'\),`, "$1 $2 uint32 // $3"),       //fields
		initRule(`(\s*)\('(.*)',\s*'<q(.*)'\),`, "$1 $2 int64 // $3"),        //fields
		initRule(`(\s*)\('(.*)',\s*'<Q(.*)'\),`, "$1 $2 uint64 // $3"),       //fields
		initRule(`(\s*)\('(.*)',\s*'(\d)+s(.*)'\),`, "$1 $2 [$3]byte // $4"), //fields
		//initRule(`(\s*)\('(.*)',\s*'"\\x(.*)'\),`, "$1 $2 byte // padding $3"), //fields

		initRule(`(\s*)\("(.*)",\s*"<B(.*)"\),`, "$1 $2 byte // $3"),         //fields
		initRule(`(\s*)\("(.*)",\s*"<h(.*)"\),`, "$1 $2 int16 // $3"),        //fields
		initRule(`(\s*)\("(.*)",\s*"<H(.*)"\),`, "$1 $2 uint16 // $3"),       //fields
		initRule(`(\s*)\("(.*)",\s*"<I(.*)"\),`, "$1 $2 uint32 // $3"),       //fields
		initRule(`(\s*)\("(.*)",\s*"<L(.*)"\),`, "$1 $2 uint32 // $3"),       //fields
		initRule(`(\s*)\("(.*)",\s*"<q(.*)"\),`, "$1 $2 int64 // $3"),        //fields
		initRule(`(\s*)\("(.*)",\s*"<Q(.*)"\),`, "$1 $2 uint64 // $3"),       //fields
		initRule(`(\s*)\("(.*)",\s*"(\d)+s(.*)"\),`, "$1 $2 [$3]byte // $4"), //fields
		//initRule(`(\s*)\("(.*)",\s*""\\x(.*)"\),`, "$1 $2 byte // padding $3"), //fields

	}
	dir, _ := os.Getwd()
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(info.Name(), ".py") {
			goFile := strings.ReplaceAll(path, ".py", ".go")
			if shouldNotUpdate(goFile) {
				return nil
			}
			b, err := ioutil.ReadFile(path) // just pass the file name
			if err != nil {
				fmt.Print(err)
			}
			for _, r := range rules {
				b = r.pattern.ReplaceAll(b, r.template)
			}
			ioutil.WriteFile(goFile, b, 0644)
		}
		return nil
	})
}

func shouldNotUpdate(path string) bool {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.HasPrefix(string(b), `// don't touch`)
}
