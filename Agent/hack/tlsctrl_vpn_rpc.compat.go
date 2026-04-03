package tlsctrlvpn

import (
    "context"
    "fmt"
    "io"

    memclnt "github.com/srmkv/tlsctrl-agent/internal/vppbinapi/memclnt"
    api "go.fd.io/govpp/api"
)

type RPCService interface {
    TlsctrlVpnPoolSet(ctx context.Context, in *TlsctrlVpnPoolSet) (*TlsctrlVpnPoolSetReply, error)
    TlsctrlVpnProfileSet(ctx context.Context, in *TlsctrlVpnProfileSet) (*TlsctrlVpnProfileSetReply, error)
    TlsctrlVpnConnectConfigGet(ctx context.Context, in *TlsctrlVpnConnectConfigGet) (*TlsctrlVpnConnectConfigGetReply, error)
    TlsctrlVpnTunnelOpen(ctx context.Context, in *TlsctrlVpnTunnelOpen) (*TlsctrlVpnTunnelOpenReply, error)
    TlsctrlVpnTunnelClose(ctx context.Context, in *TlsctrlVpnTunnelClose) (*TlsctrlVpnTunnelCloseReply, error)
    TlsctrlVpnPoolDump(ctx context.Context, in *TlsctrlVpnPoolDump) (RPCService_TlsctrlVpnPoolDumpClient, error)
    TlsctrlVpnProfileDump(ctx context.Context, in *TlsctrlVpnProfileDump) (RPCService_TlsctrlVpnProfileDumpClient, error)
    TlsctrlVpnTunnelDump(ctx context.Context, in *TlsctrlVpnTunnelDump) (RPCService_TlsctrlVpnTunnelDumpClient, error)
}

type serviceClient struct { conn api.Connection }

func NewServiceClient(conn api.Connection) RPCService { return &serviceClient{conn: conn} }

func (c *serviceClient) TlsctrlVpnPoolSet(ctx context.Context, in *TlsctrlVpnPoolSet) (*TlsctrlVpnPoolSetReply, error) {
    out := new(TlsctrlVpnPoolSetReply)
    if err := c.conn.Invoke(ctx, in, out); err != nil { return nil, err }
    return out, api.RetvalToVPPApiError(out.Retval)
}
func (c *serviceClient) TlsctrlVpnProfileSet(ctx context.Context, in *TlsctrlVpnProfileSet) (*TlsctrlVpnProfileSetReply, error) {
    out := new(TlsctrlVpnProfileSetReply)
    if err := c.conn.Invoke(ctx, in, out); err != nil { return nil, err }
    return out, api.RetvalToVPPApiError(out.Retval)
}
func (c *serviceClient) TlsctrlVpnConnectConfigGet(ctx context.Context, in *TlsctrlVpnConnectConfigGet) (*TlsctrlVpnConnectConfigGetReply, error) {
    out := new(TlsctrlVpnConnectConfigGetReply)
    if err := c.conn.Invoke(ctx, in, out); err != nil { return nil, err }
    return out, api.RetvalToVPPApiError(out.Retval)
}
func (c *serviceClient) TlsctrlVpnTunnelOpen(ctx context.Context, in *TlsctrlVpnTunnelOpen) (*TlsctrlVpnTunnelOpenReply, error) {
    out := new(TlsctrlVpnTunnelOpenReply)
    if err := c.conn.Invoke(ctx, in, out); err != nil { return nil, err }
    return out, api.RetvalToVPPApiError(out.Retval)
}
func (c *serviceClient) TlsctrlVpnTunnelClose(ctx context.Context, in *TlsctrlVpnTunnelClose) (*TlsctrlVpnTunnelCloseReply, error) {
    out := new(TlsctrlVpnTunnelCloseReply)
    if err := c.conn.Invoke(ctx, in, out); err != nil { return nil, err }
    return out, api.RetvalToVPPApiError(out.Retval)
}

type RPCService_TlsctrlVpnPoolDumpClient interface { Recv() (*TlsctrlVpnPoolDetails, error); api.Stream }
type serviceClient_TlsctrlVpnPoolDumpClient struct { api.Stream }
func (c *serviceClient) TlsctrlVpnPoolDump(ctx context.Context, in *TlsctrlVpnPoolDump) (RPCService_TlsctrlVpnPoolDumpClient, error) {
    stream, err := c.conn.NewStream(ctx)
    if err != nil { return nil, err }
    x := &serviceClient_TlsctrlVpnPoolDumpClient{stream}
    if err := x.Stream.SendMsg(in); err != nil { return nil, err }
    if err = x.Stream.SendMsg(&memclnt.ControlPing{}); err != nil { return nil, err }
    return x, nil
}
func (c *serviceClient_TlsctrlVpnPoolDumpClient) Recv() (*TlsctrlVpnPoolDetails, error) {
    msg, err := c.Stream.RecvMsg()
    if err != nil { return nil, err }
    switch m := msg.(type) {
    case *TlsctrlVpnPoolDetails:
        return m, nil
    case *memclnt.ControlPingReply:
        if err = c.Stream.Close(); err != nil { return nil, err }
        return nil, io.EOF
    default:
        return nil, fmt.Errorf("unexpected message: %T %v", m, m)
    }
}

type RPCService_TlsctrlVpnProfileDumpClient interface { Recv() (*TlsctrlVpnProfileDetails, error); api.Stream }
type serviceClient_TlsctrlVpnProfileDumpClient struct { api.Stream }
func (c *serviceClient) TlsctrlVpnProfileDump(ctx context.Context, in *TlsctrlVpnProfileDump) (RPCService_TlsctrlVpnProfileDumpClient, error) {
    stream, err := c.conn.NewStream(ctx)
    if err != nil { return nil, err }
    x := &serviceClient_TlsctrlVpnProfileDumpClient{stream}
    if err := x.Stream.SendMsg(in); err != nil { return nil, err }
    if err = x.Stream.SendMsg(&memclnt.ControlPing{}); err != nil { return nil, err }
    return x, nil
}
func (c *serviceClient_TlsctrlVpnProfileDumpClient) Recv() (*TlsctrlVpnProfileDetails, error) {
    msg, err := c.Stream.RecvMsg()
    if err != nil { return nil, err }
    switch m := msg.(type) {
    case *TlsctrlVpnProfileDetails:
        return m, nil
    case *memclnt.ControlPingReply:
        if err = c.Stream.Close(); err != nil { return nil, err }
        return nil, io.EOF
    default:
        return nil, fmt.Errorf("unexpected message: %T %v", m, m)
    }
}

type RPCService_TlsctrlVpnTunnelDumpClient interface { Recv() (*TlsctrlVpnTunnelDetails, error); api.Stream }
type serviceClient_TlsctrlVpnTunnelDumpClient struct { api.Stream }
func (c *serviceClient) TlsctrlVpnTunnelDump(ctx context.Context, in *TlsctrlVpnTunnelDump) (RPCService_TlsctrlVpnTunnelDumpClient, error) {
    stream, err := c.conn.NewStream(ctx)
    if err != nil { return nil, err }
    x := &serviceClient_TlsctrlVpnTunnelDumpClient{stream}
    if err := x.Stream.SendMsg(in); err != nil { return nil, err }
    if err = x.Stream.SendMsg(&memclnt.ControlPing{}); err != nil { return nil, err }
    return x, nil
}
func (c *serviceClient_TlsctrlVpnTunnelDumpClient) Recv() (*TlsctrlVpnTunnelDetails, error) {
    msg, err := c.Stream.RecvMsg()
    if err != nil { return nil, err }
    switch m := msg.(type) {
    case *TlsctrlVpnTunnelDetails:
        return m, nil
    case *memclnt.ControlPingReply:
        if err = c.Stream.Close(); err != nil { return nil, err }
        return nil, io.EOF
    default:
        return nil, fmt.Errorf("unexpected message: %T %v", m, m)
    }
}
