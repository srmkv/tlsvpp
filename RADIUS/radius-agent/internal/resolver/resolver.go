package resolver

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	"radius-agent/internal/model"
	"radius-agent/internal/store"
)

var ErrUserNotFound = errors.New("radius user not found")

type Service struct {
	store store.Store
}

func New(st store.Store) *Service { return &Service{store: st} }

// ResolveUser maps a RADIUS user to a VPN policy by combining their group
// memberships with the configured group/attr mappings.
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

	// Resolve VPN profile and policy set from group mappings (first match wins).
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

	// Collect all reply items (user + groups).
	allReplyItems := append([]model.RadiusAttr(nil), user.ReplyItems...)
	for _, g := range groups {
		if grp := snap.Groups[g]; grp != nil {
			allReplyItems = append(allReplyItems, grp.ReplyItems...)
		}
	}

	// Process reply items: extract timeouts, tags, attr mappings.
	for _, item := range allReplyItems {
		name := strings.ToLower(item.Name)
		switch name {
		case "session-timeout":
			if v, err := strconv.Atoi(strings.TrimSpace(item.Value)); err == nil && v > 0 {
				if out.SessionTimeout == 0 {
					out.SessionTimeout = v
				}
			}
		case "idle-timeout":
			if v, err := strconv.Atoi(strings.TrimSpace(item.Value)); err == nil && v > 0 {
				if out.IdleTimeout == 0 {
					out.IdleTimeout = v
				}
			}
		case "filter-id", "class":
			if tag := strings.TrimSpace(item.Value); tag != "" {
				out.Tags = append(out.Tags, tag)
			}
		}
		// Attr mappings can override/add tags.
		for _, am := range attrMappings {
			if !am.Enabled || !strings.EqualFold(am.AttrName, item.Name) {
				continue
			}
			if am.AttrValueLike == "" ||
				strings.Contains(strings.ToLower(item.Value), strings.ToLower(am.AttrValueLike)) {
				if tv := strings.TrimSpace(am.TargetValue); tv != "" {
					out.Tags = append(out.Tags, tv)
				}
			}
		}
	}
	return out, nil
}
