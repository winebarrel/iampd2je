package main

import (
	"io"
	"log"
	"os"

	"github.com/alecthomas/kong"
	"github.com/winebarrel/iampd2j"
)

var version string

func init() {
	log.SetFlags(0)
}

type options struct {
	Files   []string `arg:"" type:"existingfile" help:"TODO"`
	Version kong.VersionFlag
}

func parseArgs() *options {
	opts := &options{}
	parser := kong.Must(opts, kong.Vars{"version": version})
	parser.Model.HelpFlag.Help = "Show help."

	if _, err := parser.Parse(os.Args[1:]); err != nil {
		parser.FatalIfErrorf(err)
	}

	return opts
}

func main() {
	opts := parseArgs()

	for _, f := range opts.Files {
		var r io.ReadCloser

		if f == "-" {
			r = io.NopCloser(os.Stdin)
		} else {
			var err error
			r, err = os.Open(f)

			if err != nil {
				log.Fatal(err)
			}
		}

		err := convert(r, f, os.Stdout)

		if err != nil {
			log.Fatal(err)
		}
	}
}

func convert(src io.ReadCloser, filename string, out io.Writer) error {
	defer src.Close()
	bs, err := io.ReadAll(src)

	if err != nil {
		return err
	}

	return iampd2j.Convert(bs, filename, out)
}
