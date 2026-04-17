package freeradius_sql

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"radius-agent/internal/model"
	"sort"
	"strings"
	"time"
)

func loadSnapshot(ctx context.Context, db *sql.DB, src model.Source) (*model.Snapshot, error) {
	snap := &model.Snapshot{
		SourceID:  src.ID,
		CreatedAt: time.Now().UTC(),
		Users:     map[string]*model.RadiusUser{},
		Groups:    map[string]*model.RadiusGroup{},
	}

	if err := loadUserAttrs(ctx, db, qRadcheck, snap, "user_check"); err != nil {
		return nil, fmt.Errorf("load radcheck: %w", err)
	}
	if err := loadUserAttrs(ctx, db, qRadreply, snap, "user_reply"); err != nil {
		return nil, fmt.Errorf("load radreply: %w", err)
	}
	if err := loadGroupAttrs(ctx, db, qRadgroupcheck, snap, "group_check"); err != nil {
		return nil, fmt.Errorf("load radgroupcheck: %w", err)
	}
	if err := loadGroupAttrs(ctx, db, qRadgroupreply, snap, "group_reply"); err != nil {
		return nil, fmt.Errorf("load radgroupreply: %w", err)
	}
	if err := loadUserGroups(ctx, db, snap); err != nil {
		return nil, fmt.Errorf("load radusergroup: %w", err)
	}

	snap.Diagnostics.UserCount = len(snap.Users)
	snap.Diagnostics.GroupCount = len(snap.Groups)
	hash, err := snapshotHash(snap)
	if err != nil {
		return nil, err
	}
	snap.Diagnostics.Hash = hash
	snap.Revision = hash
	return snap, nil
}

func loadUserAttrs(ctx context.Context, db *sql.DB, query string, snap *model.Snapshot, scope string) error {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var username, attr, op, value string
		if err := rows.Scan(&username, &attr, &op, &value); err != nil {
			return err
		}
		username = normalize(username)
		u := ensureUser(snap, username)
		item := model.RadiusAttr{Name: attr, Op: op, Value: value, Scope: scope}
		if scope == "user_check" {
			u.CheckItems = append(u.CheckItems, item)
		} else {
			u.ReplyItems = append(u.ReplyItems, item)
		}
	}
	return rows.Err()
}

func loadGroupAttrs(ctx context.Context, db *sql.DB, query string, snap *model.Snapshot, scope string) error {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var groupName, attr, op, value string
		if err := rows.Scan(&groupName, &attr, &op, &value); err != nil {
			return err
		}
		groupName = normalize(groupName)
		g := ensureGroup(snap, groupName)
		item := model.RadiusAttr{Name: attr, Op: op, Value: value, Scope: scope}
		if scope == "group_check" {
			g.CheckItems = append(g.CheckItems, item)
		} else {
			g.ReplyItems = append(g.ReplyItems, item)
		}
	}
	return rows.Err()
}

func loadUserGroups(ctx context.Context, db *sql.DB, snap *model.Snapshot) error {
	rows, err := db.QueryContext(ctx, qRadusergroup)
	if err != nil {
		return err
	}
	defer rows.Close()

	type rowItem struct {
		group string
		prio  int
	}
	bucket := map[string][]rowItem{}
	for rows.Next() {
		var username, groupName string
		var priority int
		if err := rows.Scan(&username, &groupName, &priority); err != nil {
			return err
		}
		username = normalize(username)
		groupName = normalize(groupName)
		bucket[username] = append(bucket[username], rowItem{group: groupName, prio: priority})
		g := ensureGroup(snap, groupName)
		if g.Priority == 0 || priority < g.Priority {
			g.Priority = priority
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for username, items := range bucket {
		sort.SliceStable(items, func(i, j int) bool { return items[i].prio < items[j].prio })
		u := ensureUser(snap, username)
		for _, it := range items {
			u.Groups = append(u.Groups, it.group)
		}
	}
	return nil
}

func ensureUser(snap *model.Snapshot, username string) *model.RadiusUser {
	u := snap.Users[username]
	if u != nil {
		return u
	}
	u = &model.RadiusUser{Username: username}
	snap.Users[username] = u
	return u
}

func ensureGroup(snap *model.Snapshot, groupName string) *model.RadiusGroup {
	g := snap.Groups[groupName]
	if g != nil {
		return g
	}
	g = &model.RadiusGroup{Name: groupName}
	snap.Groups[groupName] = g
	return g
}

func normalize(v string) string {
	return strings.TrimSpace(strings.ToLower(v))
}

func snapshotHash(snap *model.Snapshot) (string, error) {
	b, err := json.Marshal(snap)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
