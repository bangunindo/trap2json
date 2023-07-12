package main

import (
	"context"
	"flag"
	"github.com/bangunindo/trap2json/logger"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
	"path"
)

const defaultConfigPath = "/etc/trap2json"

func main() {
	configPath := flag.String(
		"config",
		path.Join(defaultConfigPath, "config.yml"),
		"path to config file",
	)
	snmptrapdConfPath := flag.String(
		"generate",
		"",
		"generate snmptrapd.conf",
	)
	flag.Parse()
	logger.InitLogger(logger.Config{
		Level:  zerolog.InfoLevel,
		Format: logger.FormatConsole,
	}, os.Stderr)
	c, err := parseConfig(*configPath)
	if err != nil {
		log.Fatal().
			Str("module", "config").
			Err(err).
			Msg("failed reading environment/configuration file")
	}
	logger.InitLogger(c.Logger, os.Stderr)
	if *snmptrapdConfPath != "" {
		log.Info().Str("module", "generate").Msg("generating snmptrapd.conf file")
		if err = c.SnmpTrapD.Serialize(*snmptrapdConfPath); err != nil {
			log.Fatal().
				Str("module", "generate").
				Err(err).
				Msg("failed generating snmptrapd.conf file")
		}
	} else {
		log.Info().Msg("starting trap2json")
		Run(context.Background(), c, os.Stdin, false)
		log.Info().Msg("trap2json exited")
	}
}
