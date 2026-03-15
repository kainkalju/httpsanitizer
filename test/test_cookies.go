package main
import (
	"fmt"
	"net/http"
)
func main() {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.AddCookie(&http.Cookie{Name: "Foo", Value: "1"})
	req.AddCookie(&http.Cookie{Name: "Bar", Value: "2"})
	req.AddCookie(&http.Cookie{Name: "Test", Value: "3"})
	
	jar := req.Cookies()
	req.Header.Del("Cookie")
	
	delNames := []string{"Foo", "Bar"}
	
	for _, name := range delNames {
		for _, c := range jar {
			if name != c.Name {
				req.AddCookie(c)
			}
		}
	}
	fmt.Printf("Cookies: %v\n", req.Cookies())
}
