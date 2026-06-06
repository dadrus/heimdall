package nonce

import "time"

type createConfig struct {
	binding [nonceBindingSize]byte
}

type validateConfig struct {
	binding [nonceBindingSize]byte
	maxAge  time.Duration
}

type CreateOption interface {
	applyCreate(cfg *createConfig)
}

type ValidateOption interface {
	applyValidate(cfg *validateConfig)
}

type bindingOption [nonceBindingSize]byte

func (o bindingOption) applyCreate(cfg *createConfig)     { cfg.binding = o }
func (o bindingOption) applyValidate(cfg *validateConfig) { cfg.binding = o }

func WithBinding(binding [nonceBindingSize]byte) bindingOption { return binding }

type maxAgeOption time.Duration

func (o maxAgeOption) applyValidate(cfg *validateConfig) { cfg.maxAge = time.Duration(o) }

func WithMaxAge(maxAge time.Duration) maxAgeOption { return maxAgeOption(maxAge) }
