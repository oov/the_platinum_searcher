package main

import (
	"fmt"
	flags "github.com/jessevdk/go-flags"
	"github.com/monochromegane/terminal"
	"github.com/monochromegane/the_platinum_searcher/search"
	"github.com/monochromegane/the_platinum_searcher/search/option"
	"os"
	"runtime"
	"strings"
)

var opts option.Option

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {

	parser := flags.NewParser(&opts, flags.Default)
	parser.Name = "pt"
	parser.Usage = "[OPTIONS] PATTERN [PATH]"

	args, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}

	opts.Proc = runtime.NumCPU()

	if !terminal.IsTerminal(os.Stdout) {
		opts.NoColor = true
		opts.NoGroup = true
	}

	if len(args) == 0 {
		parser.WriteHelp(os.Stdout)
		os.Exit(1)
	}

	var root = "."
	if len(args) == 2 {
		root = strings.TrimRight(args[1], "\"")
		_, err := os.Lstat(root)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}
	}

	searcher := search.Searcher{root, args[0], &opts}
	searcher.Search()
}
