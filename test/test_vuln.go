package main

import (
	"fmt"
	"strings"

	valid "github.com/asaskevich/govalidator"
)

func isAlphaNum(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_'
}
func main() {
	// 1. Test SQLia regex bug
	value := "A_SELECT SELECT 1"
	s := strings.ToUpper(value)
	kw := "SELECT"

	idx := strings.Index(s, kw)
	before := idx == 0 || !isAlphaNum(rune(s[idx-1]))
	after := idx+len(kw) >= len(s) || !isAlphaNum(rune(s[idx+len(kw)]))

	fmt.Printf("SQLia bypassing:\n")
	fmt.Printf("String: %s\n", value)
	fmt.Printf("First index of SELECT: %d\n", idx)
	fmt.Printf("Match: %v\n", before && after)

	// 2. Test IsFilePath logic
	path := "../../etc/passwd"
	isValid, _ := valid.IsFilePath(path)
	fmt.Printf("\nFilePath logic:\n")
	fmt.Printf("Path: %s\n", path)
	fmt.Printf("isValid: %v\n", isValid)

	// How validateFilePath handles it:
	if isValid == false {
		path = valid.SafeFileName(path)
		fmt.Printf("Sanitized: %s\n", path)
	} else {
		fmt.Printf("Sanitized: %s (Unchanged!)\n", path)
	}
}
