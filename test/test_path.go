package main

import (
	"fmt"

	valid "github.com/asaskevich/govalidator"
)

func evaluate(path string) {
	isValid, _ := valid.IsFilePath(path)
	fmt.Printf("Path: %-20s -> isValid: %v\n", path, isValid)
	if !isValid {
		fmt.Printf("   Sanitized: %s\n", valid.SafeFileName(path))
	} else {
		fmt.Printf("   Sanitized: %s (Unchanged)\n", path)
	}
}
func main() {
	evaluate("../../etc/passwd")
	evaluate("/etc/passwd")
	evaluate("C:\\Windows\\System32\\cmd.exe")
	evaluate("some/relative/path")
	evaluate("/foo/bar/../baz")
}
