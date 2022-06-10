package Router

import (
	"fmt"
	"net/http"
	"reflect"
	"time"

	datb "github.com/INebotov/SP/Back/Auth/DataBase"
	dats "github.com/INebotov/SP/Back/Auth/DataStructs"
	jwte "github.com/INebotov/SP/Back/Auth/JwtEngine"
	other "github.com/INebotov/SP/Back/Auth/Other"
	"github.com/gin-gonic/gin"
)

type Router struct {
	Router          *gin.Engine
	Port            uint
	AuthToolkit     jwte.Auth
	DataBaseToolKit datb.DataBase
}

func (r *Router) CreateRouter() {
	r.Router = gin.New()
	r.Router.Use(gin.Logger())
	r.Router.POST("/auth", r.Auth)
	r.Router.GET("/refresh", Refresh)
}

func (r Router) CheckTockensFromCookie(c *gin.Context) bool {
	acess, err1 := c.Request.Cookie("acess")
	refresh, err2 := c.Request.Cookie("refresh")

	if err1 != nil || err2 != nil {
		// Brocken Pair - Recreate
		return false
	}
	tk, err := r.AuthToolkit.CheckAndRipp(acess.Value)
	refr, refrerr := r.AuthToolkit.CheckAndRippRefresh(refresh.Value)
	if err != nil || refrerr != nil {
		// Brocken Pair - Recreate
		return false
	}

	return tk.Valid() == nil && refr.Valid() == nil
}

func (r Router) Auth(c *gin.Context) {
	var cren dats.UserArrived
	cren.Login = c.PostForm("login")
	cren.Password = c.PostForm("password")

	if r.CheckTockensFromCookie(c) {
		c.JSON(http.StatusAlreadyReported, gin.H{
			"message": "Already Have Valid Tocken",
			"err":     "AHVT-001",
		})
		return
	}

	user, err := r.DataBaseToolKit.GetUser(cren.Login)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "There Is No User In Our Databse",
			"err":     "NUID-020",
		})
		return
	}
	if !reflect.DeepEqual(user.Password, other.NewSHA256(cren.Password)) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Wrong User Crentetails",
			"err":     "WUCP-140",
		})
		return
	}

	tockenpair := r.AuthToolkit.GetKeyPair(user)

	exp := time.Now().Add(r.AuthToolkit.AcessTTL).String()
	c.Header("Set-Cookie", fmt.Sprintf("acess=%s; Expires=%s; refresh=%s; Expires=%s;", tockenpair.Acess, exp, tockenpair.Refresh, exp))
	c.JSON(http.StatusOK, gin.H{
		"acess":      tockenpair.Acess,
		"refresh":    tockenpair.Refresh,
		"isincookie": true,
		"message":    "Ok Authorissated!",
		"err":        "",
	})
}

func Refresh(c *gin.Context) {
	// TODO: Refresh in JWT
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	})
}
