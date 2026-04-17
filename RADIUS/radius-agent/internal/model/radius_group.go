package model

type RadiusGroup struct {
	Name       string       `json:"name"`
	Priority   int          `json:"priority"`
	CheckItems []RadiusAttr `json:"check_items"`
	ReplyItems []RadiusAttr `json:"reply_items"`
}
