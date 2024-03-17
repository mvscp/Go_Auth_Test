package app

import (
	"log"
)

var errLogger *log.Logger

func Log() {
	//errLogger = log.New(os.Stderr, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)
	errLogger = log.Default()
}
