package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type UserArrived struct {
	Login    string
	Password string
}
type Router struct {
	Router *gin.Engine
	Port   uint
}

func (r *Router) CreateRouter() {
	r.Router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
}
