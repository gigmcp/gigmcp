package api

// Exported shims for whitebox tests in package api_test.

var (
	EnvelopeMux = envelopeMux
	WriteErr    = writeErr
	CodeNotFound = codeNotFound
)
