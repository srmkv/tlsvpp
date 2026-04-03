package vppclient

import (
	"context"
	"time"

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

	SetClientApps(ctx context.Context, username string, commandID string, generatedAt time.Time, apps []model.AppInfo) error
	GetApps(ctx context.Context, username string) (model.AppsSnapshot, error)

	SetCommand(ctx context.Context, username string, cmd model.Command) error
	GetCommand(ctx context.Context, username string) (model.Command, error)
	SetListenerConfig(ctx context.Context, listenAddr string, listenPort int, serverCertPEM, serverKeyPEM, caCertPEM string) error
SetVPNPool(ctx context.Context, name, subnet, gateway string, leaseSeconds int) error
SetVPNProfile(ctx context.Context, name, pool string, fullTunnel bool, dnsServers, includeRoutes, excludeRoutes string, mtu, mssClamp int) error
}
