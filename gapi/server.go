package gapi

import (
	"fmt"

	db "github.com/alperdemr/go-back/db/sqlc"
	"github.com/alperdemr/go-back/pb"
	"github.com/alperdemr/go-back/token"
	"github.com/alperdemr/go-back/util"
)


type Server struct {
	pb.UnimplementedGoBackServer
	config util.Config
	store db.Store
	tokenMaker token.Maker
}


func NewServer(config util.Config,store db.Store) (*Server,error) {
	tokenMaker,err := token.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		return nil,fmt.Errorf("cannot create token maker: %w",err)
	}
	server := &Server{config:config,store: store,tokenMaker: tokenMaker}

	return server,nil
}
