package main
import (
	"fmt"
	"net/url"
)
func main() {
	v, err := url.QueryUnescape("100% genuine")
	fmt.Printf("v=%q, err=%v\n", v, err)
}
