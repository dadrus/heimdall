package secrets2

type referenceScope string

const (
	referenceScopeInternal referenceScope = "internal"
	referenceScopeRule     referenceScope = "rule"
)

type scopedReference struct {
	Reference

	namespace string
	scope     referenceScope
}

type referenceFactory func(Reference) scopedReference

func internalRef(ref Reference) scopedReference {
	return scopedReference{
		Reference: ref,
		scope:     referenceScopeInternal,
	}
}

func ruleRef(ref Reference, namespace string) scopedReference {
	return scopedReference{
		Reference: ref,
		namespace: namespace,
		scope:     referenceScopeRule,
	}
}

func namespacedRuleRef(namespace string) referenceFactory {
	return func(ref Reference) scopedReference {
		return ruleRef(ref, namespace)
	}
}
