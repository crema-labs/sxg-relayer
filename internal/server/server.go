package server

import (
	"github.com/crema-labs/sxg-go/internal/handler"

	"github.com/gin-gonic/gin"
)

type Server struct {
	router   *gin.Engine
	priv_key string
}

func NewServer(priv_key string) *Server {
	r := gin.Default()
	s := &Server{router: r, priv_key: priv_key}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	hpr := handler.HandleProofRequest{
		PrivKey: s.priv_key,
	}
	s.router.POST("/", hpr.HandlePost)
}

func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
}
