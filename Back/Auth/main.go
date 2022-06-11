package main

import (
	"fmt"

	conf "github.com/INebotov/SP/Back/Auth/Configuration"
	datb "github.com/INebotov/SP/Back/Auth/DataBase"
	ath "github.com/INebotov/SP/Back/Auth/JwtEngine"
	rout "github.com/INebotov/SP/Back/Auth/Router"
)

// TODO: Redis key-userid value tocken
// TODO: Diagrams correct in Api

func main() {
	c := conf.Config{}
	a := ath.Auth{}
	db := datb.DataBase{}
	r := rout.Router{}
	c.Configure("/home/ivan/Desktop/SP/config/auth-config.yaml", &a, &db, &r)
	r.CreateRouter()
	r.Router.Run(fmt.Sprintf(":%d", r.Port))
}
