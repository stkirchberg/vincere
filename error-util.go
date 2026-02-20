package main

type myError struct {
	s string
}

func (e *myError) Error() string {
	return e.s
}

func myNewError(text string) error {
	return &myError{text}
}
