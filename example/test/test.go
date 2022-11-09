package main

import (
	"fmt"
	"time"
)

func read(x chan int) {
	for {
		a := <- x
		fmt.Printf("a: %v\n", a)
	}
}

func write(x chan int){
	for i := 0; i < 10; i++ {
		if i == 5 {
			time.Sleep(time.Second)
		} 
		x <- i
	}
}
func main() {
	s := make(chan int)
	go read(s)
	go write(s)
	time.Sleep(time.Second*2)
}

