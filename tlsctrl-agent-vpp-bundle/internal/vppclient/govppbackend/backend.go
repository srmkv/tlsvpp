//go:build govpp

package govppbackend

import (
	"context"
	"fmt"
	"github.com/srmkv/tlsctrl-agent/internal/model"
	"github.com/srmkv/tlsctrl-agent/internal/vppclient"
)

type Backend struct { socket string }
func New(socket string) vppclient.Client { return &Backend{socket: socket} }
func (b *Backend) UpsertUser(ctx context.Context, user model.User) error { return fmt.Errorf("govpp backend not wired yet") }
func (b *Backend) DeleteUser(ctx context.Context, username string) error { return fmt.Errorf("govpp backend not wired yet") }
func (b *Backend) ReissueUser(ctx context.Context, username, certSerial string) error { return fmt.Errorf("govpp backend not wired yet") }
func (b *Backend) ListUsers(ctx context.Context) ([]model.User, error) { return nil, fmt.Errorf("govpp backend not wired yet") }
func (b *Backend) ListSessions(ctx context.Context) ([]model.Session, error) { return nil, fmt.Errorf("govpp backend not wired yet") }
func (b *Backend) DisconnectSession(ctx context.Context, username string) error { return fmt.Errorf("govpp backend not wired yet") }
func (b *Backend) ClientHeartbeat(ctx context.Context, hb model.ClientHeartbeat) error { return fmt.Errorf("govpp backend not wired yet") }
func (b *Backend) SetClientApps(ctx context.Context, username string, apps []model.AppInfo) error { return fmt.Errorf("govpp backend not wired yet") }
func (b *Backend) SetCommand(ctx context.Context, username string, cmd model.Command) error { return fmt.Errorf("govpp backend not wired yet") }
func (b *Backend) GetCommand(ctx context.Context, username string) (model.Command, error) { return model.Command{}, fmt.Errorf("govpp backend not wired yet") }
