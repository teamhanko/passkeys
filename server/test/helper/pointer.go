package helper

// Of is a helper routine that allocates a new any value
// to store v and returns a pointer to it.
func ToPointer[Value any](v Value) *Value {
	return &v
}
