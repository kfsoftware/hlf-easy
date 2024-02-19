package config

import "os"

type SaveOutputWriter struct {
	savedOutput []byte
}

func (so *SaveOutputWriter) GetSavedOutput() []byte {
	return so.savedOutput
}
func (so *SaveOutputWriter) Write(p []byte) (n int, err error) {
	so.savedOutput = append(so.savedOutput, p...)
	return os.Stdout.Write(p)
}
