package print

import (
	"fmt"
	"github.com/monochromegane/the_platinum_searcher/search/option"
	"strings"
)

const (
	ColorReset      = "\x1b[0m\x1b[K"
	ColorLineNumber = "\x1b[1;33m"  /* yellow with black background */
	ColorPath       = "\x1b[1;32m"  /* bold green */
	ColorMatch      = "\x1b[30;43m" /* black with yellow background */
)

type Match struct {
	LineNum int
	Match   string
}

type Params struct {
	Pattern string
	Path    string
	Matches []*Match
}

type Printer struct {
	In     chan *Params
	Done   chan bool
	Option *option.Option
}

func (self *Printer) Print() {
	for arg := range self.In {

		if len(arg.Matches) == 0 {
			continue
		}

		if !self.Option.NoGroup {
			self.printPath(arg.Path)
			fmt.Printf("\n")
		}
		for _, v := range arg.Matches {
			if v == nil {
				continue
			}
			if self.Option.NoGroup {
				self.printPath(arg.Path)
			}
			if !self.Option.FilesWithMatches {
				self.printLineNumber(v.LineNum)
				self.printMatch(arg.Pattern, v.Match)
				fmt.Printf("\n")
			}
		}
		if !self.Option.NoGroup && !self.Option.FilesWithMatches {
			fmt.Printf("\n")
		}
	}
	self.Done <- true
}

func (self *Printer) printPath(path string) {
	if self.Option.NoColor {
		fmt.Printf("%s", path)
	} else {
		fmt.Printf("%s%s%s", ColorPath, path, ColorReset)
	}
	if !self.Option.FilesWithMatches {
		fmt.Printf(":")
	}
}
func (self *Printer) printLineNumber(lineNum int) {
	if self.Option.NoColor {
		fmt.Printf("%d:", lineNum)
	} else {
		fmt.Printf("%s%d%s:", ColorLineNumber, lineNum, ColorReset)
	}
}
func (self *Printer) printMatch(pattern, match string) {
	if self.Option.NoColor {
		fmt.Printf("%s", match)
	} else {
		fmt.Printf("%s", strings.Replace(match, pattern, ColorMatch+pattern+ColorReset, -1))
	}
}
