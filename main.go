package main

import (
	"fmt"
	casbin "github.com/casbin/casbin/v2"
)

func main() {
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
	
	hasPolicy,_ := e.Enforce("Leia", "uploadFile", "write") // false
	fmt.Println("Leia", "uploadFile", "write", hasPolicy)
	hasPolicy,_ = e.Enforce("Han", "uploadFile", "write") // false
	fmt.Println("Han", "uploadFile", "write", hasPolicy)
	hasPolicy,_ = e.Enforce("R2-D2", "/balances", "read") // false
	fmt.Println("R2-D2", "/balances", "read", hasPolicy)
	hasPolicy,_ = e.Enforce("Obi-Wan", "/houses", "read") // true
	fmt.Println("Obi-Wan", "/houses", "read", hasPolicy)
	hasPolicy,_ = e.Enforce("Leia", "/condos", "write") // true
	fmt.Println("Leia", "/condos", "write", hasPolicy)
	hasPolicy,_ = e.Enforce("Han", "/condos", "write") // true
	fmt.Println("Han", "/condos", "write", hasPolicy)
	hasPolicy,_ = e.Enforce("Luke", "/balances", "read") // true
	fmt.Println("Luke", "/balances", "read", hasPolicy)
	hasPolicy,_ = e.Enforce("R2-D2", "uploadFile", "write") // true
	fmt.Println("R2-D2", "uploadFile", "write", hasPolicy)
	hasPolicy,_ = e.Enforce("Obi-Wan", "/houses", "write") // false
	fmt.Println("Obi-Wan", "/houses", "write", hasPolicy)
	_,_ = e.AddNamedGroupingPolicy("g2", "Obi-Wan", "admin")
	hasPolicy,_ = e.Enforce("Obi-Wan", "/houses", "write") // true
	fmt.Println("Obi-Wan", "/houses", "write", hasPolicy)
	_,_ = e.RemoveNamedGroupingPolicy("g2", "Leia")
	hasPolicy,_ = e.Enforce("Leia", "/condo", "write") // false
	fmt.Println("Leia", "/condos", "write", hasPolicy)
}

// 1. Crear archivo de configuracion (.conf)
// 3. Agregar los usuarios con sus respectivos permisos
// 4. Probar que
//   a) Leia y Han no pueden subir archivo uploadFile
//   b) R2 no pueda ver los balances
//   c) Obi-Wan solo puede ver sus casas
//   d) Leia o Han pueden agregar un nuevo condo
//   e) Luke puede ver el balance de su condo
//   f) R2 puede agregar un archivo
//   g) Obi-Wan no puede crear una nueva casa
//   h) al darle permisos a Obi-Wan de agregar casa, puede agregar casa
//   i) al remover a Leia del grupo de staff, ya no puede crear condo
// 5. Repetir el punto 4 sin el 3

// 2. Agregar adapter de postgres