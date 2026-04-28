package nonce

const (
	noncePayloadVersion  = byte(1)
	nonceRandomSize      = 32
	nonceBindingSize     = 32
	noncePayloadSize     = 1 + 8 + nonceBindingSize
	nonceAEADNonceSize   = 12
	nonceAEADTagSize     = 16
	maxEncryptedNonceLen = 4096
	nonceAEADKeySize     = 32
)

var nonceHKDFInfo = "heimdall/nonce/aes-256-gcm/v1"
