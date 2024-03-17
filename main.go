package main

import (
	"awesomeProject/app"
	"log"
	"net/http"
)

func main() {
	app.ConnectDB()
	app.Log()
	http.HandleFunc("/auth", app.Auth)
	http.HandleFunc("/refresh", app.Refresh)
	log.Fatal(http.ListenAndServe(":3000", nil))
}
