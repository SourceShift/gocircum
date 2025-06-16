package gocircum

import (
	"gocircum/core"
	"gocircum/core/config"
	"gocircum/interfaces"
)

// Engine represents the circumvention engine.
type Engine struct {
	coreEngine *core.Engine
}

// NewEngine creates a new instance of the circumvention engine from a config file.
func NewEngine(configPath string) (interfaces.Engine, error) {
	fingerprints, err := config.LoadFingerprintsFromFile(configPath)
	if err != nil {
		return nil, err
	}

	coreEngine, err := core.NewEngine(fingerprints)
	if err != nil {
		return nil, err
	}
	return &Engine{coreEngine: coreEngine}, nil
}

// Start initializes and starts the engine.
func (e *Engine) Start() error {
	return e.coreEngine.Start()
}

// Stop gracefully stops the engine.
func (e *Engine) Stop() error {
	return e.coreEngine.Stop()
}

// Status returns the current operational status of the engine.
func (e *Engine) Status() (string, error) {
	return e.coreEngine.Status()
}
