package Router

import (
	"fmt"
	"net/http"
	"reflect"
	"time"

	datb "github.com/INebotov/SP/Back/Auth/DataBase"
	dats "github.com/INebotov/SP/Back/Auth/DataStructs"
	errs "github.com/INebotov/SP/Back/Auth/Erroring"
	ath "github.com/INebotov/SP/Back/Auth/JwtEngine"
	vl "github.com/INebotov/SP/Back/Auth/Validations"

	other "github.com/INebotov/SP/Back/Auth/Other"

	"github.com/gin-gonic/gin"
)

type Router struct {
	Router          *gin.Engine
	Port            uint
	DataBaseToolKit datb.DataBase
	AuthToolkit     ath.Auth
}

func (r *Router) CreateRouter() {
	r.Router = gin.New()
	r.Router.Use(gin.Logger())
	r.Router.POST("/auth", r.Auth)
	r.Router.GET("/refresh", r.Refresh)
	r.Router.GET("/logout", r.Logout)
	r.Router.POST("/reg", r.Reg)
}

// Auth
func (r Router) CheckTockensFromCookie(c *gin.Context) bool {
	acess, err1 := c.Request.Cookie("acess")
	refresh, err2 := c.Request.Cookie("refresh")
	tk, err3 := r.AuthToolkit.CheckAndRipp(acess.Value)
	valid, err4 := r.AuthToolkit.CheckRefresh(refresh.Value)

	return tk.Valid() == nil || other.CompareErrors(err1, err2, err3, err4) == nil || valid
}
func (r Router) GetUserLP(c *gin.Context) (res dats.UserArrived, err error) {
	login := c.PostForm("login")
	password := other.NewSHA256(c.PostForm("password"))
	if !vl.ValidateLogin(login) || !vl.ValidatePassword(password) {
		return dats.UserArrived{}, errs.ErrFooNotPassValidation
	}
	res.Login = login
	res.Password = password
	return res, nil
}
func (r Router) MakeError(c *gin.Context, ec errs.TypycalError) {
	c.JSON(ec.Code, gin.H{
		"message": ec.Message,
		"err":     ec.Err,
	})
}
func (r Router) Auth(c *gin.Context) {
	if r.CheckTockensFromCookie(c) {
		r.MakeError(c, errs.AHVT)
		return
	}
	user, err := r.GetUserLP(c)
	if err != nil {
		r.MakeError(c, errs.IC)
		return
	}
	realuser, err := r.DataBaseToolKit.GetUser(user.Login)
	if err != nil {
		r.MakeError(c, errs.NEU)
		return
	}
	if !reflect.DeepEqual(realuser.Password, user.Password) {
		r.MakeError(c, errs.IP)
		return
	}
	acess, err1 := r.AuthToolkit.GenerateAcsess(realuser)
	refresh, err2 := r.AuthToolkit.GenerateRefresh(realuser)
	if other.CompareErrors(err1, err2) != nil {
		r.MakeError(c, errs.ISE)
		return
	}
	aexp := time.Now().Add(r.AuthToolkit.AcessTTL).String()
	rexp := time.Now().Add(r.AuthToolkit.RefreshTTL).String()
	c.Header("Set-Cookie", fmt.Sprintf("acess=%s; Expires=%s; refresh=%s; Expires=%s;", acess, aexp, refresh, rexp))
	c.JSON(http.StatusOK, gin.H{
		"message": "Ok! Authoriszed! In Cookie: true",
		"err":     "",
		"acess":   acess,
		"refresh": refresh,
	})
}

// Reg
func (r Router) ValidRegReqest(c *gin.Context) (res bool, user dats.UserCrenditals) {
	user.Email = c.PostForm("email")
	user.Login = c.PostForm("login")
	user.Role = c.PostForm("role")
	user.Password = other.NewSHA256(c.PostForm("password"))
	res = (vl.ValidateEmail(user.Email) && vl.ValidateLogin(user.Login) && vl.ValidatePassword(user.Password) && vl.ValidateRole(user.Role))
	return res, user
}
func (r Router) Reg(c *gin.Context) {
	if r.CheckTockensFromCookie(c) {
		r.MakeError(c, errs.AHVT)
		return
	}
	ok, user := r.ValidRegReqest(c)
	if !ok {
		r.MakeError(c, errs.NVR)
		return
	}
	if !r.DataBaseToolKit.CheckUnical(user) {
		r.MakeError(c, errs.AH)
		return
	}

	//TODO: IOFC CHecking

	if r.DataBaseToolKit.Register(&user) != nil {
		r.MakeError(c, errs.ISE)
		return
	}
	acess, err1 := r.AuthToolkit.GenerateAcsess(user)
	refresh, err2 := r.AuthToolkit.GenerateRefresh(user)
	if other.CompareErrors(err1, err2) != nil {
		r.MakeError(c, errs.ISE)
		return
	}
	aexp := time.Now().Add(r.AuthToolkit.AcessTTL).String()
	rexp := time.Now().Add(r.AuthToolkit.RefreshTTL).String()
	c.Header("Set-Cookie", fmt.Sprintf("acess=%s; Expires=%s; refresh=%s; Expires=%s;", acess, aexp, refresh, rexp))
	c.JSON(http.StatusOK, gin.H{
		"message": "Ok! Registarated! Keys Has Been Equired! In Cookie: true",
		"err":     "",
		"acess":   acess,
		"refresh": refresh,
	})
}

func (r Router) CheckJustnuse(c *gin.Context) (refresh string, ok bool) {
	ref, err := c.Request.Cookie("refresh")
	refresh = ref.Value
	valid, err1 := r.AuthToolkit.CheckRefresh(refresh)
	if other.CompareErrors(err, err1) != nil || !valid {
		return "", false
	}
	return refresh, true
}
func (r Router) Refresh(c *gin.Context) {
	token, ok := r.CheckJustnuse(c)
	if !ok {
		r.MakeError(c, errs.TII)
		return
	}
	r.AuthToolkit.DeleteRefresh(token)
	r.AuthToolkit.GenerateRefresh()
}
func (r Router) Logout(c *gin.Context) {}

// func (r Router) Reg(c *gin.Context) {
// 	cren := dats.UserCrenditals{}
// 	login := c.PostForm("login")
// 	if !r.DataBaseToolKit.CheckUnical(login, "login") {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"message": "Login Already Allocated",
// 			"err":     "LAA-289",
// 		})
// 		return

// 	}
// 	cren.Login = login
// 	cren.Password = other.NewSHA256(c.PostForm("password"))
// 	email := c.PostForm("email")
// 	if !r.DataBaseToolKit.CheckUnical(email, "email") || !other.ValidEmail(email) {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"message": "Email Is Already Allocated or Incorrect",
// 			"err":     "EIB-082",
// 		})
// 		return
// 	}
// 	cren.Email = email
// 	role := c.PostForm("role")
// 	if !(role == "Student" || role == "Teacher" || role == "User") {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"message": "Role Not Correct",
// 			"err":     "RNC-038",
// 		})
// 		return
// 	}
// 	cren.Role = role
// 	if r.DataBaseToolKit.Register(&cren) == nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{
// 			"message": "Internal Server Error",
// 			"err":     "ISE-500",
// 		})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{
// 		"message": "Ok! Registred",
// 		"err":     "",
// 	})
// }

// func (r Router) Logout(c *gin.Context) {

// 	acess, err := c.Request.Cookie("acess")
// 	if err != nil {
// 		r.DataBaseToolKit.Redis.Del(acess.Value)
// 	}
// 	refresh, err := c.Request.Cookie("refresh")
// 	if err == nil {
// 		r.DataBaseToolKit.Redis.Del(refresh.Value)
// 	}

// 	c.Header("Set-Cookie", "Set-Cookie: acess=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; Set-Cookie: refresh=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
// 	c.JSON(http.StatusAlreadyReported, gin.H{
// 		"message": "Logged Out",
// 		"err":     "",
// 	})
// }

// func (r Router) Auth(c *gin.Context) {
// 	var cren dats.UserArrived
// 	cren.Login = c.PostForm("login")
// 	cren.Password = c.PostForm("password")

// 	if r.CheckTockensFromCookie(c) {
// 		c.JSON(http.StatusAlreadyReported, gin.H{
// 			"message": "Already Have Valid Tocken",
// 			"err":     "AHVT-001",
// 		})
// 		return
// 	}

// 	user, err := r.DataBaseToolKit.GetUser(cren.Login)

// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"message": "There Is No User In Our Databse",
// 			"err":     "NUID-020",
// 		})
// 		return
// 	}
// 	if !reflect.DeepEqual(user.Password, other.NewSHA256(cren.Password)) {
// 		c.JSON(http.StatusUnauthorized, gin.H{
// 			"message": "Wrong User Crentetails",
// 			"err":     "WUCP-140",
// 		})
// 		return
// 	}

// 	tockenpair, err := r.AuthToolkit.GetKeyPair(user)

// 	exp := time.Now().Add(r.AuthToolkit.AcessTTL).String()
// 	c.Header("Set-Cookie", fmt.Sprintf("acess=%s; Expires=%s; refresh=%s; Expires=%s;", tockenpair.Acess, exp, tockenpair.Refresh, exp))
// 	c.JSON(http.StatusOK, gin.H{
// 		"acess":      tockenpair.Acess,
// 		"refresh":    tockenpair.Refresh,
// 		"isincookie": true,
// 		"message":    "Ok Authorissated!",
// 		"err":        "",
// 	})
// }

// func Refresh(c *gin.Context) {
// 	// TODO: Refresh in JWT
// 	c.JSON(http.StatusOK, gin.H{
// 		"message": "pong",
// 	})
// }
