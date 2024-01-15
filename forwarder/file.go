package forwarder

import (
	"io"
	"os"
)

type FileConfig struct {
	// Path for json log. Make sure the user has sufficient permission to write
	Path string
}

type File struct {
	Base
}

func (f *File) Run() {
	defer f.cancel()
	defer f.logger.Info().Msg("forwarder exited")
	f.logger.Info().Msg("starting forwarder")
	var fOut io.WriteCloser
	var err error
	switch f.config.File.Path {
	case "":
		fOut = os.Stdout
	default:
		fOut, err = os.OpenFile(f.config.File.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	if err != nil {
		f.logger.
			Fatal().
			Err(err).
			Msg("failed opening file")
		return
	}
	defer fOut.Close()
	for m := range f.ReceiveChannel() {
		m.Compile(f.CompilerConf)
		if m.Metadata.Skip {
			f.ctrFiltered.Inc()
			continue
		}
		mJson := append(m.Metadata.MessageJSON, []byte("\n")...)
		if _, err = fOut.Write(mJson); err != nil {
			f.Retry(m, err)
		} else {
			f.ctrSucceeded.Inc()
		}
	}
}

func NewFile(c Config, idx int) Forwarder {
	fwd := &File{
		NewBase(c, idx),
	}
	go fwd.Run()
	return fwd
}
