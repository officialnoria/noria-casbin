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
	rules := [][]string{
		{"admin", "mutations"},

		{"staff", "createAccount"},
		{"staff", "updateAccount"},
		{"staff", "deleteAccount"},
		{"staff", "createCondo"},
		{"staff", "updateCondo"},
		{"staff", "deleteCondo"},
		{"staff", "createHouse"},
		{"staff", "updateHouse"},
		{"staff", "deleteHouse"},

		{"owner", "houses"},
		{"owner", "balances"},

		{"user", "balances"},
	}
	_, _ = e.AddNamedPolicies("p", rules)

	mutations := [][]string {
		{"createAcountant", "mutations"},
		{"createAccount", "mutations"},
		{"updateAccount", "mutations"},
		{"deleteAccount", "mutations"},
		{"createApplicationpayment", "mutations"},
		{"updateApplicationpayment", "mutations"},
		{"deleteApplicationpayment", "mutations"},
		{"approvePayment", "mutations"},
		{"createBalance", "mutations"},
		{"updateBalance", "mutations"},
		{"deleteBalance", "mutations"},
		{"createCondo", "mutations"},
		{"updateCondo", "mutations"},
		{"deleteCondo", "mutations"},
		{"createDiscount", "mutations"},
		{"updateDiscount", "mutations"},
		{"deleteDiscount", "mutations"},
		{"createHouse", "mutations"},
		{"updateHouse", "mutations"},
		{"deleteHouse", "mutations"},
		{"createProvider", "mutations"},
		{"updateProvider", "mutations"},
		{"deleteProvider", "mutations"},
		{"updateUnrecognizeddeposit", "mutations"},
	}
	_,_ = e.AddNamedGroupingPolicies("g", mutations)

	queries := [][]string {
		{"accounts", "queries"},
		{"accountants", "queries"},
		{"applicationpayments", "queries"},
		{"balances", "queries"},
		{"condos", "queries"},
		{"deposits", "queries"},
		{"discounts", "queries"},
		{"expenses", "queries"},
		{"houses", "queries"},
		{"providers", "queries"},
		{"unrecognizeddeposits", "queries"},
	}
	_,_ = e.AddNamedGroupingPolicies("g2", queries)

	users := [][]string {
		{"Luke", "user"},
		{"Leia", "staff"},
		{"Han", "staff"},
		{"Obi-Wan", "owner"},
		{"Yoda", "admin"},
		{"R2-D2", "admin"},
	}
	_,_ = e.AddNamedGroupingPolicies("g3", users)
	
	tests := [][]string {
		{"Leia", "createApplicationpayment"},
		{"Han", "createApplicationpayment"},
		{"R2-D2", "balances"},
		{"Obi-Wan", "houses"},
		{"Leia", "createCondo"},
		{"Han", "createCondo"},
		{"Luke", "balances"},
		{"R2-D2", "createApplicationpayment"},
		{"Obi-Wan", "createHouse"},
	}
		
	for _, v := range tests {
		hasPolicy, _ := e.Enforce(v[0], v[1])
		fmt.Println(v, hasPolicy)
	}
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