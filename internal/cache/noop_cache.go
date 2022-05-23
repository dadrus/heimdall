package cache

import "time"

type noopCache struct{}

func (c noopCache) Start() {}

func (c noopCache) Stop() {}

func (c noopCache) Get(_ string) any { return nil }

func (c noopCache) Set(_ string, _ any, _ time.Duration) {}

func (c noopCache) Delete(_ string) {}
