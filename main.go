package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/CiscoCloud/consul-cli/commands"
)

const Name = "consul-cli"
const Version = "0.2.0"

func main() {
	log.SetOutput(ioutil.Discard)

	root := commands.Init(Name, Version)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(root.Err, err)
		os.Exit(1)
	}

	os.Exit(0)
}
