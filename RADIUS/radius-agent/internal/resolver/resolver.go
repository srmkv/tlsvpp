package resolver

import (
	"context"
	"errors"
	"radius-agent/internal/model"
	"radius-agent/internal/store"
	"sort"
	"strings"
)

var ErrUserNotFound = errors.New("radius user not found")

type Service struct {
	store store.Store
}

func New(st store.Store) *Service { return &Service{store: st} }

func (s *Service) ResolveUser(ctx context.Context, sourceID, username string) (*model.ResolvedPolicy, error) {
	snap, err := s.store.GetLatestSnapshot(ctx, sourceID)
	if err != nil {
		return nil, err
	}
	username = strings.TrimSpace(strings.ToLower(username))
	user := snap.Users[username]
	if user == nil {
		return nil, ErrUserNotFound
	}
	groups := append([]string(nil), user.Groups...)
	sort.Strings(groups)
	groupMappings, _ := s.store.ListGroupMappings(ctx)
	attrMappings, _ := s.store.ListAttrMappings(ctx)

	out := &model.ResolvedPolicy{
		Username:      username,
		SourceID:      sourceID,
		Groups:        groups,
		RawReplyItems: append([]model.RadiusAttr(nil), user.ReplyItems...),
	}

	for _, g := range groups {
		for _, gm := range groupMappings {
			if gm.Enabled && strings.EqualFold(gm.GroupName, g) {
				if out.VPNProfile == "" {
					out.VPNProfile = gm.VPNProfile
				}
				if out.PolicySet == "" {
					out.PolicySet = gm.PolicySet
				}
			}
		}
	}

	allReplyItems := append([]model.RadiusAttr(nil), user.ReplyItems...)
	for _, g := range groups {
		if grp := snap.Groups[g]; grp != nil {
			allReplyItems = append(allReplyItems, grp.ReplyItems...)
		}
	}
	for _, item := range allReplyItems {
		switch strings.ToLower(item.Name) {
		case "session-timeout":
			// parse intentionally omitted in scaffold
		case "idle-timeout":
		case "filter-id", "class":
			out.Tags = append(out.Tags, item.Value)
		}
		for _, am := range attrMappings {
			if !am.Enabled || !strings.EqualFold(am.AttrName, item.Name) {
				continue
			}
			if am.AttrValueLike == "" || strings.Contains(strings.ToLower(item.Value), strings.ToLower(am.AttrValueLike)) {
				out.Tags = append(out.Tags, am.TargetValue)
			}
		}
	}
	return out, nil
}
