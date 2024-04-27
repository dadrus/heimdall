package config

type EncodedSlashesHandling string

const (
	EncodedSlashesOff        EncodedSlashesHandling = "off"
	EncodedSlashesOn         EncodedSlashesHandling = "on"
	EncodedSlashesOnNoDecode EncodedSlashesHandling = "no_decode"
)
