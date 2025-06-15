package interfaces

// Engine defines the public interface for the circumvention engine.
type Engine interface {
	// Start initializes and starts the engine.
	Start() error
	// Stop gracefully stops the engine.
	Stop() error
	// Status returns the current operational status of the engine.
	Status() (string, error)
}
