package semconv

import "go.opentelemetry.io/otel/attribute"

const (
	CertificateServiceKey      = attribute.Key("service")
	CertificateIssuerKey       = attribute.Key("issuer")
	CertificateSerialNumberKey = attribute.Key("serial_nr")
	CertificateSubjectKey      = attribute.Key("subject")
	CertificateDNSNameKey      = attribute.Key("dns_names")
)

func CertificateService(value string) attribute.KeyValue {
	return CertificateServiceKey.String(value)
}

func CertificateIssuer(value string) attribute.KeyValue {
	return CertificateIssuerKey.String(value)
}

func CertificateSerialNumber(value string) attribute.KeyValue {
	return CertificateSerialNumberKey.String(value)
}

func CertificateSubject(value string) attribute.KeyValue {
	return CertificateSubjectKey.String(value)
}

func CertificateDNSName(value string) attribute.KeyValue {
	return CertificateDNSNameKey.String(value)
}

const (
	RuleIDKey   = attribute.Key("rule.id")
	RuleSetKey  = attribute.Key("ruleset.name")
	ProviderKey = attribute.Key("provider")
	ResultKey   = attribute.Key("result")
)

func RuleID(value string) attribute.KeyValue   { return RuleIDKey.String(value) }
func RuleSet(value string) attribute.KeyValue  { return RuleSetKey.String(value) }
func Provider(value string) attribute.KeyValue { return ProviderKey.String(value) }
func Result(value string) attribute.KeyValue   { return ResultKey.String(value) }

const (
	StepIDKey        = attribute.Key("step.id")
	MechanismNameKey = attribute.Key("mechanism.name")
	MechanismKindKey = attribute.Key("mechanism.kind")
)

func StepID(value string) attribute.KeyValue        { return StepIDKey.String(value) }
func MechanismKind(value string) attribute.KeyValue { return MechanismKindKey.String(value) }
func MechanismName(value string) attribute.KeyValue { return MechanismNameKey.String(value) }
