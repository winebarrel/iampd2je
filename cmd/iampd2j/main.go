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
	Files   []string `arg:"" help:"Terraform files to convert (use \"-\" for stdin)."`
	Version kong.VersionFlag
}

func parseArgs() *options {
	opts := &options{}
	parser := kong.Must(opts,
		kong.Name("iampd2j"),
		kong.Description("Convert aws_iam_policy_document data sources to jsonencode() expressions."),
		kong.Vars{"version": version},
	)
	parser.Model.HelpFlag.Help = "Show help."

	if _, err := parser.Parse(os.Args[1:]); err != nil {
		parser.FatalIfErrorf(err)
	}

	return opts
}

func main() {
	opts := parseArgs()
	conv := iampd2j.NewConverter()

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

		if err := convert(conv, r, f); err != nil {
			log.Fatal(err)
		}
	}
}

func convert(conv *iampd2j.Converter, src io.ReadCloser, filename string) error {
	defer src.Close()
	bs, err := io.ReadAll(src)

	if err != nil {
		return err
	}

	return conv.Convert(bs, filename)
}
