package model

type GroupMapping struct {
	GroupName  string `json:"group_name"`
	VPNProfile string `json:"vpn_profile"`
	PolicySet  string `json:"policy_set"`
	TrustLevel string `json:"trust_level"`
	Enabled    bool   `json:"enabled"`
}

type AttrMapping struct {
	ID            int64  `json:"id"`
	AttrName      string `json:"attr_name"`
	AttrValueLike string `json:"attr_value_like"`
	SessionOption string `json:"session_option"`
	TargetValue   string `json:"target_value"`
	Enabled       bool   `json:"enabled"`
}
