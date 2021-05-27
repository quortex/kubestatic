// Package helper provide some basic utility functions.
package helper

// StringPointerOrNil converts a string value to a string pointer or nil if empty string.
func StringPointerOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Int64PointerOrNil returns a pointer on given int or nil if zero
func Int64PointerOrNil(i int64) *int64 {
	if i == 0 {
		return nil
	}
	return &i
}

// ContainsString returns if given slice contains string.
func ContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// RemoveString remove given string from given slice and returns it.
func RemoveString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}
