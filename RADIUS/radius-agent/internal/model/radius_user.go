package model

type RadiusUser struct {
	Username   string       `json:"username"`
	Disabled   bool         `json:"disabled"`
	Groups     []string     `json:"groups"`
	CheckItems []RadiusAttr `json:"check_items"`
	ReplyItems []RadiusAttr `json:"reply_items"`
}
