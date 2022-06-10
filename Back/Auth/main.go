package main

func main() {
	c := Config{}
	a := Auth{}
	db := DataBase{}
	r := Router{}
	c.Configure("./config/config.yaml", &a, &db, &r)

}
