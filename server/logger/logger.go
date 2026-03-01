package logger

import (
	"log"
	"os"
)

var (
	Info  = log.New(os.Stdout, "[INFO]  ", log.LstdFlags|log.Lshortfile)
	Warn  = log.New(os.Stdout, "[WARN]  ", log.LstdFlags|log.Lshortfile)
	Error = log.New(os.Stderr, "[ERROR] ", log.LstdFlags|log.Lshortfile)
	Fatal = log.New(os.Stderr, "[FATAL] ", log.LstdFlags|log.Lshortfile)
)
