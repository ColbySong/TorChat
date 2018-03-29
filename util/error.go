package util

import (
	"log"
	"os"
)

var (
	ErrLog *log.Logger = log.New(os.Stderr, "[LOG] ", log.Lshortfile|log.LUTC|log.Lmicroseconds)
	OutLog *log.Logger = log.New(os.Stderr, "[LOG] ", log.Lshortfile|log.LUTC|log.Lmicroseconds)
)

func HandleNonFatalError(msg string, e error) {
	if e != nil {
		ErrLog.Printf("[ERROR] %s, err = %s\n", msg, e.Error())
	}
}

func HandleFatalError(msg string, e error) {
	if e != nil {
		ErrLog.Fatalf("[FATAL ERROR] %s, err = %s\n", msg, e.Error())
	}
}

