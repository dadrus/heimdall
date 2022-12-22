package pkix

import "crypto/x509"

var keyUsages = map[KeyUsage]string{ //nolint:gochecknoglobals
	KeyUsage(x509.KeyUsageDigitalSignature):  "DigitalSignature",
	KeyUsage(x509.KeyUsageContentCommitment): "ContentCommitment",
	KeyUsage(x509.KeyUsageKeyEncipherment):   "KeyEncipherment",
	KeyUsage(x509.KeyUsageDataEncipherment):  "DataEncipherment",
	KeyUsage(x509.KeyUsageKeyAgreement):      "KeyAgreement",
	KeyUsage(x509.KeyUsageCertSign):          "CertSign",
	KeyUsage(x509.KeyUsageCRLSign):           "CRLSign",
	KeyUsage(x509.KeyUsageEncipherOnly):      "EncipherOnly",
	KeyUsage(x509.KeyUsageDecipherOnly):      "DecipherOnly",
}

type KeyUsage x509.KeyUsage

func (k KeyUsage) String() string {
	if name, ok := keyUsages[k]; ok {
		return name
	}

	return "Unknown"
}
