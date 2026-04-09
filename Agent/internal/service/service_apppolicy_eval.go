package service

import (
	"context"
	"regexp"
	"strings"

	"github.com/srmkv/tlsctrl-agent/internal/model"
)

func (s *Service) EvaluateAppPolicy(ctx context.Context, req model.AppPolicyEvaluateRequest) (model.AppPolicyDecision, error) {
	resolved, err := s.ResolveAppPolicy(ctx, req.Username, req.Profile)
	if err != nil {
		return model.AppPolicyDecision{}, err
	}
	decision := model.AppPolicyDecision{
		PolicyVersion: resolved.PolicyVersion,
		Username:      resolved.Username,
		Profile:       resolved.Profile,
		Allow:         true,
		Policies:      resolved.Policies,
	}
	if len(resolved.Policies) == 0 {
		return decision, nil
	}
	items := normalizeInventory(req.Apps)
	stage := strings.ToLower(strings.TrimSpace(req.Stage))
	for _, p := range resolved.Policies {
		if !p.Enabled {
			continue
		}
		switch stage {
		case "client", "client_preconnect", "preconnect":
			if !p.CheckOnClient {
				continue
			}
		case "server", "server_detect", "postconnect":
			if !p.CheckOnServer {
				continue
			}
		default:
			if !p.CheckOnClient && !p.CheckOnServer {
				continue
			}
		}
		for _, pat := range p.Patterns {
			patternText := strings.TrimSpace(pat.Value)
			if patternText == "" {
				continue
			}
			re := compilePolicyPattern(patternText, strings.TrimSpace(pat.Type))
			if re == nil {
				continue
			}
			for _, item := range items {
				hay := inventoryHaystack(item)
				if hay == "" || !re.MatchString(hay) {
					continue
				}
				decision.Allow = false
				decision.Matches = append(decision.Matches, model.AppPolicyMatch{
					PolicyID:   strings.TrimSpace(p.ID),
					PolicyName: strings.TrimSpace(firstNonEmpty(p.Name, p.ID, "Политика")),
					Pattern:    patternText,
					App:        strings.TrimSpace(firstNonEmpty(item.Name, item.Exe, item.Category)),
				})
				if decision.Message == "" {
					decision.Message = strings.TrimSpace(firstNonEmpty(p.Message, "У вас обнаружено запрещенное приложение"))
				}
			}
		}
	}
	return decision, nil
}

func normalizeInventory(items model.AppInventoryList) []model.AppInventoryItem {
	seen := map[string]struct{}{}
	out := make([]model.AppInventoryItem, 0, len(items))
	for _, it := range items {
		it.Name = strings.TrimSpace(it.Name)
		it.Exe = strings.TrimSpace(it.Exe)
		it.Category = strings.TrimSpace(it.Category)
		key := strings.ToLower(it.Name + "\n" + it.Exe + "\n" + it.Category)
		if key == "\n\n" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, it)
	}
	return out
}

func inventoryHaystack(it model.AppInventoryItem) string {
	parts := []string{strings.TrimSpace(it.Name), strings.TrimSpace(it.Exe), strings.TrimSpace(it.Category)}
	return strings.ToLower(strings.Join(parts, "\n"))
}

func compilePolicyPattern(value, typ string) *regexp.Regexp {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	typ = strings.ToLower(strings.TrimSpace(typ))
	if typ == "regex" {
		re, err := regexp.Compile(`(?i)` + value)
		if err != nil {
			return nil
		}
		return re
	}
	quoted := regexp.QuoteMeta(value)
	quoted = strings.ReplaceAll(quoted, `\*`, `.*`)
	re, err := regexp.Compile(`(?i)` + quoted)
	if err != nil {
		return nil
	}
	return re
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
