package srp

import (
	"fmt"

	gosrp "github.com/opencoff/go-srp"
)

type Environment struct {
	srp *gosrp.SRP
}

func NewEnvironment(bits int) (*Environment, error) {
	s, err := gosrp.New(bits)
	if err != nil {
		return nil, fmt.Errorf("initializing SRP environment: %w", err)
	}
	return &Environment{srp: s}, nil
}

func (e *Environment) SRP() *gosrp.SRP {
	return e.srp
}
