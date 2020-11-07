package main

import (
	"fmt"
	casbin "github.com/casbin/casbin/v2"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		panic("Must provide arguments")
	}
	character := os.Args[1]
	object := os.Args[2]
	action := os.Args[3]
	e, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		panic(err)
	}
	rules := [][] string {
		{"admin", "urls", "read"},
		{"admin", "urls", "write"},

		{"staff", "/accounts", "read"},
		{"staff", "/accounts", "write"},
		{"staff", "/houses", "read"},
		{"staff", "/condos", "read"},
		{"staff", "/condos", "write"},

		{"owner", "/houses", "read"},
		{"owner", "/houses", "write"},
		{"owner", "/balances", "read"},

		{"user", "/balances", "read"},
	}
	_,_ = e.AddNamedPolicies("p", rules)

	domains := [][]string {
		{"/balances", "urls"},
		{"/accounts", "urls"},
		{"/houses", "urls"},
		{"/condos", "urls"},
		{"uploadFile", "urls"},
	}
	_,_ = e.AddNamedGroupingPolicies("g", domains)

	users := [][]string {
		{"Luke", "user"},
		{"Leia", "staff"},
		{"Han", "staff"},
		{"Obi-Wan", "owner"},
		{"Yoda", "admin"},
		{"R2-D2", "anonymous"},
	}
	_,_ = e.AddNamedGroupingPolicies("g2", users)
	
	hasPolicy,_ := e.Enforce(character, object, action)
	fmt.Println(hasPolicy)
}