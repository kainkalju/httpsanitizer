package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
)

func main() {
	var k = koanf.New(".")
	cfg := file.Provider("config.yaml")
	k.Load(cfg, yaml.Parser())
	var wg sync.WaitGroup
	// 5 readers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				k.Exists("server.addr")
				k.String("server.addr")
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}
	// 1 writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 5; j++ {
			k.Load(cfg, yaml.Parser())
			time.Sleep(10 * time.Millisecond)
		}
	}()
	wg.Wait()
	fmt.Println("Done without panic")
}
