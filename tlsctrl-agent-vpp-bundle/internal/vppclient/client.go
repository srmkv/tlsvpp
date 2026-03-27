package vppclient

import (
	"context"

	"github.com/srmkv/tlsctrl-agent/internal/model"
)

type Client interface {
	UpsertUser(ctx context.Context, user model.User) error
	DeleteUser(ctx context.Context, username string) error
	ReissueUser(ctx context.Context, username, certSerial string) error

	ListUsers(ctx context.Context) ([]model.User, error)
	ListSessions(ctx context.Context) ([]model.Session, error)

	DisconnectSession(ctx context.Context, username string) error
	ClientHeartbeat(ctx context.Context, hb model.ClientHeartbeat) error
	SetClientApps(ctx context.Context, username string, apps []model.AppInfo) error

	SetCommand(ctx context.Context, username string, cmd model.Command) error
	GetCommand(ctx context.Context, username string) (model.Command, error)
}
