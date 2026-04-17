package model

type ResolvedPolicy struct {
	Username       string       `json:"username"`
	SourceID       string       `json:"source_id"`
	Groups         []string     `json:"groups"`
	VPNProfile     string       `json:"vpn_profile"`
	PolicySet      string       `json:"policy_set"`
	SessionTimeout int          `json:"session_timeout"`
	IdleTimeout    int          `json:"idle_timeout"`
	Tags           []string     `json:"tags"`
	RawReplyItems  []RadiusAttr `json:"raw_reply_items"`
}
