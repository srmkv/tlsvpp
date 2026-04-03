//go:build govpp

package govppbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	govpp "go.fd.io/govpp"

	"github.com/srmkv/tlsctrl-agent/internal/model"
	tlsctrl "github.com/srmkv/tlsctrl-agent/internal/vppbinapi/tlsctrl"
	tlsctrlvpn "github.com/srmkv/tlsctrl-agent/internal/vppbinapi/tlsctrlvpn"
)

type Backend struct {
	socket  string
	timeout time.Duration
	verbose bool

	mu      sync.RWMutex
	blocked map[string]bool
}

func New(socket string, timeout time.Duration, verbose bool) (*Backend, error) {
	if strings.TrimSpace(socket) == "" {
		socket = "/run/vpp/api.sock"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Backend{
		socket:  socket,
		timeout: timeout,
		verbose: verbose,
		blocked: make(map[string]bool),
	}, nil
}

func str(v string) string {
	return strings.TrimSpace(strings.TrimRight(v, "\x00"))
}

func u8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

func encodePayload(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

func encodeInterfacesJSON(ifs []model.NetworkInterface) string {
	if len(ifs) == 0 {
		return ""
	}
	data, err := json.Marshal(ifs)
	if err != nil {
		return ""
	}
	return string(data)
}

func encodeAppsReportJSON(username string, commandID string, generatedAt time.Time, apps []model.AppInfo) string {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	payload := struct {
		Username    string          `json:"username"`
		CommandID   string          `json:"command_id,omitempty"`
		GeneratedAt string          `json:"generated_at,omitempty"`
		Apps        []model.AppInfo `json:"apps"`
	}{
		Username:    strings.TrimSpace(username),
		CommandID:   strings.TrimSpace(commandID),
		GeneratedAt: generatedAt.UTC().Format(time.RFC3339),
		Apps:        apps,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(data)
}

func parseCommand(cmdType string, payload string) model.Command {
	out := model.Command{
		Type:    str(cmdType),
		Payload: map[string]any{},
	}
	if strings.TrimSpace(payload) == "" {
		return out
	}
	_ = json.Unmarshal([]byte(payload), &out.Payload)
	if id, ok := out.Payload["id"].(string); ok {
		out.ID = id
	}
	return out
}

func parseInterfacesJSON(raw string) []model.NetworkInterface {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return nil
	}
	var out []model.NetworkInterface
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

func parseAppsSnapshotJSON(username string, raw string, count uint32, generatedAtNS uint64) model.AppsSnapshot {
	out := model.AppsSnapshot{Username: strings.TrimSpace(username)}
	raw = strings.TrimSpace(raw)
	if raw != "" && raw != "null" {
		var tmp struct {
			Username    string          `json:"username"`
			CommandID   string          `json:"command_id,omitempty"`
			GeneratedAt string          `json:"generated_at,omitempty"`
			Apps        []model.AppInfo `json:"apps"`
		}
		if err := json.Unmarshal([]byte(raw), &tmp); err == nil {
			if strings.TrimSpace(tmp.Username) != "" {
				out.Username = strings.TrimSpace(tmp.Username)
			}
			out.CommandID = strings.TrimSpace(tmp.CommandID)
			if strings.TrimSpace(tmp.GeneratedAt) != "" {
				if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(tmp.GeneratedAt)); err == nil {
					out.GeneratedAt = ts.UTC()
				}
			}
			out.Apps = append([]model.AppInfo(nil), tmp.Apps...)
		}
	}
	if out.GeneratedAt.IsZero() {
		out.GeneratedAt = nsToTime(generatedAtNS)
	}
	if out.Username == "" {
		out.Username = strings.TrimSpace(username)
	}
	if out.Apps == nil && count == 0 {
		out.Apps = nil
	}
	return out
}

func statusToBool(status uint8) bool {
	return status == 1
}

func nsToTime(ns uint64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(ns)).UTC()
}

func (bkd *Backend) withConn(ctx context.Context, op string, fn func(context.Context, tlsctrl.RPCService) error) error {
	start := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok && bkd.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, bkd.timeout)
		defer cancel()
	}
	if bkd.verbose {
		log.Printf("govpp op=%s socket=%s start", op, bkd.socket)
	}
	conn, err := govpp.Connect(bkd.socket)
	if err != nil {
		log.Printf("govpp op=%s connect failed ms=%d error=%v", op, time.Since(start).Milliseconds(), err)
		return fmt.Errorf("connect govpp socket %s for %s: %w", bkd.socket, op, err)
	}
	defer conn.Disconnect()
	client := tlsctrl.NewServiceClient(conn)
	err = fn(ctx, client)
	if err != nil {
		log.Printf("govpp op=%s failed ms=%d error=%v", op, time.Since(start).Milliseconds(), err)
		return fmt.Errorf("govpp %s: %w", op, err)
	}
	if bkd.verbose {
		log.Printf("govpp op=%s ok ms=%d", op, time.Since(start).Milliseconds())
	}
	return nil
}

func (bkd *Backend) withVPNConn(ctx context.Context, op string, fn func(context.Context, tlsctrlvpn.RPCService) error) error {
	start := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok && bkd.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, bkd.timeout)
		defer cancel()
	}
	if bkd.verbose {
		log.Printf("govpp op=%s socket=%s start", op, bkd.socket)
	}
	conn, err := govpp.Connect(bkd.socket)
	if err != nil {
		log.Printf("govpp op=%s connect failed ms=%d error=%v", op, time.Since(start).Milliseconds(), err)
		return fmt.Errorf("connect govpp socket %s for %s: %w", bkd.socket, op, err)
	}
	defer conn.Disconnect()
	client := tlsctrlvpn.NewServiceClient(conn)
	err = fn(ctx, client)
	if err != nil {
		log.Printf("govpp op=%s failed ms=%d error=%v", op, time.Since(start).Milliseconds(), err)
		return fmt.Errorf("govpp %s: %w", op, err)
	}
	if bkd.verbose {
		log.Printf("govpp op=%s ok ms=%d", op, time.Since(start).Milliseconds())
	}
	return nil
}
func (bkd *Backend) UpsertUser(ctx context.Context, user model.User) error {
	if bkd.verbose {
		log.Printf("govpp request op=upsert-user username=%q enabled=%v serial=%s", str(user.Username), user.Enabled, str(user.CertSerial))
	}
	return bkd.withConn(ctx, "upsert-user", func(ctx context.Context, c tlsctrl.RPCService) error {
		_, err := c.TlsctrlUserAddDel(ctx, &tlsctrl.TlsctrlUserAddDel{
			IsAdd:      u8(true),
			Enabled:    u8(user.Enabled),
			Username:   str(user.Username),
			CertSerial: str(user.CertSerial),
		})
		return err
	})
}

func (bkd *Backend) DeleteUser(ctx context.Context, username string) error {
	if bkd.verbose {
		log.Printf("govpp request op=delete-user username=%q", str(username))
	}

	bkd.mu.Lock()
	delete(bkd.blocked, username)
	bkd.mu.Unlock()

	return bkd.withConn(ctx, "delete-user", func(ctx context.Context, c tlsctrl.RPCService) error {
		_, err := c.TlsctrlUserAddDel(ctx, &tlsctrl.TlsctrlUserAddDel{
			IsAdd:    u8(false),
			Username: str(username),
		})
		return err
	})
}

func (bkd *Backend) ReissueUser(ctx context.Context, username, certSerial string) error {
	if bkd.verbose {
		log.Printf("govpp request op=reissue-user username=%q serial=%s", str(username), str(certSerial))
	}

	bkd.mu.Lock()
	delete(bkd.blocked, username)
	bkd.mu.Unlock()

	return bkd.withConn(ctx, "reissue-user", func(ctx context.Context, c tlsctrl.RPCService) error {
		_, err := c.TlsctrlUserReissue(ctx, &tlsctrl.TlsctrlUserReissue{
			Username:   str(username),
			CertSerial: str(certSerial),
		})
		return err
	})
}

func (bkd *Backend) ListUsers(ctx context.Context) ([]model.User, error) {
	if bkd.verbose {
		log.Printf("govpp request op=list-users")
	}

	var out []model.User
	err := bkd.withConn(ctx, "list-users", func(ctx context.Context, c tlsctrl.RPCService) error {
		stream, err := c.TlsctrlUserDump(ctx, &tlsctrl.TlsctrlUserDump{})
		if err != nil {
			return err
		}
		for {
			detail, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			out = append(out, model.User{
				Username:   str(detail.Username),
				CertSerial: str(detail.CertSerial),
				Enabled:    statusToBool(detail.Enabled),
				Generation: detail.Generation,
				LastSeen:   nsToTime(detail.LastSeenUnixNs),
			})
		}
		return nil
	})
	if err == nil && bkd.verbose {
		log.Printf("govpp result op=list-users count=%d", len(out))
	}
	return out, err
}

func (bkd *Backend) ListSessions(ctx context.Context) ([]model.Session, error) {
	if bkd.verbose {
		log.Printf("govpp request op=list-sessions")
	}

	var out []model.Session
	err := bkd.withConn(ctx, "list-sessions", func(ctx context.Context, c tlsctrl.RPCService) error {
		stream, err := c.TlsctrlSessionDump(ctx, &tlsctrl.TlsctrlSessionDump{})
		if err != nil {
			return err
		}
		for {
			detail, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			sess := model.Session{
				Username:      str(detail.Username),
				CertSerial:    str(detail.CertSerial),
				SystemUser:    str(detail.SystemUser),
				OSName:        str(detail.OsName),
				OSVersion:     str(detail.OsVersion),
				SystemUptime:  str(detail.SystemUptime),
				IP:            str(detail.IP),
				MAC:           str(detail.Mac),
				Source:        str(detail.Source),
				Interfaces:    parseInterfacesJSON(str(detail.InterfacesJSON)),
				Connected:     statusToBool(detail.Status),
				ConnectedAt:   nsToTime(detail.ConnectedAtUnixNs),
				LastSeen:      nsToTime(detail.LastSeenUnixNs),
				AppsCount:     int(detail.AppsCount),
				AppsUpdatedAt: nsToTime(detail.AppsUpdatedAtUnixNs),
			}
			out = append(out, sess)
		}
		return nil
	})
	if err == nil && bkd.verbose {
		log.Printf("govpp result op=list-sessions count=%d", len(out))
	}
	return out, err
}

func (bkd *Backend) DisconnectSession(ctx context.Context, username string) error {
	if bkd.verbose {
		log.Printf("govpp request op=disconnect-session username=%q", str(username))
	}

	bkd.mu.Lock()
	delete(bkd.blocked, username)
	bkd.mu.Unlock()

	return bkd.withConn(ctx, "disconnect-session", func(ctx context.Context, c tlsctrl.RPCService) error {
		if _, err := c.TlsctrlSessionDisconnect(ctx, &tlsctrl.TlsctrlSessionDisconnect{
			Username: str(username),
		}); err != nil {
			return err
		}
		_, err := c.TlsctrlClientCommandSet(ctx, &tlsctrl.TlsctrlClientCommandSet{
			Username:    str(username),
			CommandType: "disconnect",
			Payload:     encodePayload(map[string]any{"reason": "admin_disconnect"}),
		})
		return err
	})
}

func (bkd *Backend) ClientHeartbeat(ctx context.Context, hb model.ClientHeartbeat) error {
	if bkd.verbose {
		log.Printf("govpp request op=client-heartbeat username=%q serial=%s source=%q ip=%q", hb.Username, hb.CertSerial, hb.Source, hb.IP)
	}

	bkd.mu.Lock()
	blocked := bkd.blocked[hb.Username]
	if blocked && hb.ConnectIntent == "manual_connect" {
		delete(bkd.blocked, hb.Username)
		blocked = false
	}
	bkd.mu.Unlock()

	if blocked {
		return fmt.Errorf("disconnected by admin")
	}

	interfacesJSON := encodeInterfacesJSON(hb.Interfaces)
	return bkd.withConn(ctx, "client-heartbeat", func(ctx context.Context, c tlsctrl.RPCService) error {
		if _, err := c.TlsctrlClientHeartbeat(ctx, &tlsctrl.TlsctrlClientHeartbeat{
			Username:       str(hb.Username),
			CertSerial:     str(hb.CertSerial),
			SystemUser:     str(hb.SystemUser),
			OsName:         str(hb.OSName),
			OsVersion:      str(hb.OSVersion),
			SystemUptime:   str(hb.SystemUptime),
			IP:             str(hb.IP),
			Mac:            str(hb.MAC),
			Source:         str(hb.Source),
			InterfacesJSON: interfacesJSON,
			ConnectIntent:  str(hb.ConnectIntent),
		}); err != nil {
			return err
		}
		if hb.ConnectIntent == "manual_connect" {
			_, _ = c.TlsctrlClientCommandSet(ctx, &tlsctrl.TlsctrlClientCommandSet{
				Username:    str(hb.Username),
				CommandType: "",
				Payload:     "",
			})
		}
		return nil
	})
}

func (bkd *Backend) SetClientApps(ctx context.Context, username string, commandID string, generatedAt time.Time, apps []model.AppInfo) error {
	if bkd.verbose {
		log.Printf("govpp request op=client-apps-set username=%q command-id=%q apps=%d", username, commandID, len(apps))
	}

	payload := encodeAppsReportJSON(username, commandID, generatedAt, apps)
	return bkd.withConn(ctx, "client-apps-set", func(ctx context.Context, c tlsctrl.RPCService) error {
		_, err := c.TlsctrlClientAppsSet(ctx, &tlsctrl.TlsctrlClientAppsSet{
			Username: str(username),
			Count:    uint32(len(apps)),
			Payload:  payload,
		})
		return err
	})
}

func (bkd *Backend) GetApps(ctx context.Context, username string) (model.AppsSnapshot, error) {
	if bkd.verbose {
		log.Printf("govpp request op=get-apps username=%q", username)
	}

	out := model.AppsSnapshot{Username: strings.TrimSpace(username)}
	err := bkd.withConn(ctx, "get-apps", func(ctx context.Context, c tlsctrl.RPCService) error {
		reply, err := c.TlsctrlClientAppsGet(ctx, &tlsctrl.TlsctrlClientAppsGet{Username: str(username)})
		if err != nil {
			return err
		}
		out = parseAppsSnapshotJSON(username, str(reply.Payload), reply.Count, reply.GeneratedAtUnixNs)
		return nil
	})
	if err == nil && bkd.verbose {
		log.Printf("govpp result op=get-apps username=%q apps=%d generated=%s", username, len(out.Apps), out.GeneratedAt.Format(time.RFC3339))
	}
	return out, err
}

func (bkd *Backend) SetCommand(ctx context.Context, username string, cmd model.Command) error {
	if bkd.verbose {
		log.Printf("govpp request op=set-command username=%q type=%q id=%q", username, cmd.Type, cmd.ID)
	}

	payload := cmd.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	if cmd.ID != "" {
		payload["id"] = cmd.ID
	}
	return bkd.withConn(ctx, "set-command", func(ctx context.Context, c tlsctrl.RPCService) error {
		_, err := c.TlsctrlClientCommandSet(ctx, &tlsctrl.TlsctrlClientCommandSet{
			Username:    str(username),
			CommandType: str(cmd.Type),
			Payload:     encodePayload(payload),
		})
		return err
	})
}

func (bkd *Backend) SetListenerConfig(ctx context.Context, listenAddr string, listenPort int, serverCertPEM, serverKeyPEM, caCertPEM string) error {
	if bkd.verbose {
		log.Printf("govpp request op=set-listener-config addr=%s port=%d cert-len=%d key-len=%d ca-len=%d", listenAddr, listenPort, len(serverCertPEM), len(serverKeyPEM), len(caCertPEM))
	}

	return bkd.withConn(ctx, "set-listener-config", func(ctx context.Context, c tlsctrl.RPCService) error {
		_, err := c.TlsctrlListenerConfigSet(ctx, &tlsctrl.TlsctrlListenerConfigSet{
			ListenAddr:    str(listenAddr),
			ListenPort:    uint16(listenPort),
			ServerCertPem: serverCertPEM,
			ServerKeyPem:  serverKeyPEM,
			CaCertPem:     caCertPEM,
		})
		return err
	})
}

func (bkd *Backend) GetCommand(ctx context.Context, username string) (model.Command, error) {
	if bkd.verbose {
		log.Printf("govpp request op=get-command username=%q", username)
	}

	var out model.Command
	err := bkd.withConn(ctx, "get-command", func(ctx context.Context, c tlsctrl.RPCService) error {
		reply, err := c.TlsctrlClientCommandGet(ctx, &tlsctrl.TlsctrlClientCommandGet{
			Username: str(username),
		})
		if err != nil {
			return err
		}
		out = parseCommand(reply.CommandType, reply.Payload)
		return nil
	})
	if err == nil && bkd.verbose {
		log.Printf("govpp result op=get-command username=%q type=%q id=%q", username, out.Type, out.ID)
	}
	return out, err
}

func (bkd *Backend) ForceDisconnectAll(ctx context.Context) error {
	bkd.mu.Lock()
	defer bkd.mu.Unlock()
	for username := range bkd.blocked {
		bkd.blocked[username] = true
	}
	return nil
}

func (bkd *Backend) SetVPNPool(ctx context.Context, name, subnet, gateway string, leaseSeconds int) error {
	if bkd.verbose {
		log.Printf("govpp request op=vpn-pool-set name=%q subnet=%q gateway=%q lease=%d", name, subnet, gateway, leaseSeconds)
	}
	return bkd.withVPNConn(ctx, "vpn-pool-set", func(ctx context.Context, vpnc tlsctrlvpn.RPCService) error {
		_, err := vpnc.TlsctrlVPNPoolSet(ctx, &tlsctrlvpn.TlsctrlVPNPoolSet{
			Name:         str(name),
			Subnet:       str(subnet),
			Gateway:      str(gateway),
			LeaseSeconds: uint32(leaseSeconds),
		})
		return err
	})
}

func (bkd *Backend) SetVPNProfile(ctx context.Context, name, pool string, fullTunnel bool, dnsServers, includeRoutes, excludeRoutes string, mtu, mssClamp int) error {
	if bkd.verbose {
		log.Printf("govpp request op=vpn-profile-set name=%q pool=%q full=%v mtu=%d mss=%d", name, pool, fullTunnel, mtu, mssClamp)
	}
	return bkd.withVPNConn(ctx, "vpn-profile-set", func(ctx context.Context, vpnc tlsctrlvpn.RPCService) error {
		_, err := vpnc.TlsctrlVPNProfileSet(ctx, &tlsctrlvpn.TlsctrlVPNProfileSet{
			Name:          str(name),
			Pool:          str(pool),
			FullTunnel:    fullTunnel,
			DNSServers:    str(dnsServers),
			IncludeRoutes: str(includeRoutes),
			ExcludeRoutes: str(excludeRoutes),
			Mtu:           uint16(mtu),
			MssClamp:      uint16(mssClamp),
		})
		return err
	})
}
