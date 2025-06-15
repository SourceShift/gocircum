package gocircum_test

import (
	"gocircum"
	"testing"
)

func TestEngineLifecycle(t *testing.T) {
	engine, err := gocircum.NewEngine()
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	if err := engine.Start(); err != nil {
		t.Errorf("Engine failed to start: %v", err)
	}

	status, err := engine.Status()
	if err != nil {
		t.Errorf("Failed to get engine status: %v", err)
	}

	if status != "pending" { // Current placeholder status
		t.Errorf("Expected status 'pending', got '%s'", status)
	}

	if err := engine.Stop(); err != nil {
		t.Errorf("Engine failed to stop: %v", err)
	}
}

func TestCanBeImported(t *testing.T) {
	// This test primarily exists to be run by an external project.
	// For now, we just ensure we can create the engine.
	_, err := gocircum.NewEngine()
	if err != nil {
		t.Fatalf("gocircum library could not be initialized in a test context: %v", err)
	}
	t.Log("Successfully imported and initialized gocircum library.")
}
