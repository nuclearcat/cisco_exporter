package mactable

type Interface struct {
	VLAN        string
	Count         float64
}

type Mactableentry struct {
	VLAN        int
	MAC         string
	Type        string
	Age         string
	Secure      string
	NTFY        string
	Port        string
	Count       int
}