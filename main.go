package main

import (
	"database/sql"
	"log"

	"github.com/alperdemr/go-back/api"
	db "github.com/alperdemr/go-back/db/sqlc"
	_ "github.com/lib/pq"
)

const (
	dbDriver = "postgres"
	dbSource = "postgresql://root:secret@localhost:5433/go_back?sslmode=disable"
	serverAddress = "0.0.0.0:8080"
)

func main() {
	conn,err := sql.Open(dbDriver,dbSource)
	if err != nil {
		log.Fatal("cannot connect to db:",err)
	}

	store := db.NewStore(conn)
	server := api.NewServer(store)

	err = server.Start(serverAddress)
	if err != nil {
		log.Fatal("cannot start server:",err)
	}
}