package main

import (
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
	Dir     string `arg:"" optional:"" default:"." help:"Directory containing *.tf files (default: \".\")."`
	InPlace bool   `short:"i" help:"Write changes back to files instead of stdout."`
	Verbose bool   `short:"v" help:"Verbose logging."`
	Version kong.VersionFlag
}

func parseArgs() *options {
	opts := &options{}
	parser := kong.Must(opts,
		kong.Name("iampd2j"),
		kong.Description("Inline aws_iam_policy_document data sources as jsonencode() expressions."),
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
	c := iampd2j.NewConverter(opts.Dir)
	c.Verbose = opts.Verbose
	if err := c.Run(opts.InPlace); err != nil {
		log.Fatalf("error: %v", err)
	}
}
