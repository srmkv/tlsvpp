package tlsctrlvpn

import (
    "context"
    "fmt"
    "io"

    memclnt "github.com/srmkv/tlsctrl-agent/internal/vppbinapi/memclnt"
    api "go.fd.io/govpp/api"
)

type RPCService interface {
    TlsctrlVPNPoolSet(ctx context.Context, in *TlsctrlVPNPoolSet) (*TlsctrlVPNPoolSetReply, error)
    TlsctrlVPNProfileSet(ctx context.Context, in *TlsctrlVPNProfileSet) (*TlsctrlVPNProfileSetReply, error)
    TlsctrlVPNConnectConfigGet(ctx context.Context, in *TlsctrlVPNConnectConfigGet) (*TlsctrlVPNConnectConfigGetReply, error)
    TlsctrlVPNTunnelOpen(ctx context.Context, in *TlsctrlVPNTunnelOpen) (*TlsctrlVPNTunnelOpenReply, error)
    TlsctrlVPNTunnelClose(ctx context.Context, in *TlsctrlVPNTunnelClose) (*TlsctrlVPNTunnelCloseReply, error)
    TlsctrlVPNPoolDump(ctx context.Context, in *TlsctrlVPNPoolDump) (RPCService_TlsctrlVPNPoolDumpClient, error)
    TlsctrlVPNProfileDump(ctx context.Context, in *TlsctrlVPNProfileDump) (RPCService_TlsctrlVPNProfileDumpClient, error)
    TlsctrlVPNTunnelDump(ctx context.Context, in *TlsctrlVPNTunnelDump) (RPCService_TlsctrlVPNTunnelDumpClient, error)
}

type serviceClient struct { conn api.Connection }

func NewServiceClient(conn api.Connection) RPCService { return &serviceClient{conn: conn} }

func (c *serviceClient) TlsctrlVPNPoolSet(ctx context.Context, in *TlsctrlVPNPoolSet) (*TlsctrlVPNPoolSetReply, error) {
    out := new(TlsctrlVPNPoolSetReply)
    if err := c.conn.Invoke(ctx, in, out); err != nil { return nil, err }
    return out, api.RetvalToVPPApiError(out.Retval)
}
func (c *serviceClient) TlsctrlVPNProfileSet(ctx context.Context, in *TlsctrlVPNProfileSet) (*TlsctrlVPNProfileSetReply, error) {
    out := new(TlsctrlVPNProfileSetReply)
    if err := c.conn.Invoke(ctx, in, out); err != nil { return nil, err }
    return out, api.RetvalToVPPApiError(out.Retval)
}
func (c *serviceClient) TlsctrlVPNConnectConfigGet(ctx context.Context, in *TlsctrlVPNConnectConfigGet) (*TlsctrlVPNConnectConfigGetReply, error) {
    out := new(TlsctrlVPNConnectConfigGetReply)
    if err := c.conn.Invoke(ctx, in, out); err != nil { return nil, err }
    return out, api.RetvalToVPPApiError(out.Retval)
}
func (c *serviceClient) TlsctrlVPNTunnelOpen(ctx context.Context, in *TlsctrlVPNTunnelOpen) (*TlsctrlVPNTunnelOpenReply, error) {
    out := new(TlsctrlVPNTunnelOpenReply)
    if err := c.conn.Invoke(ctx, in, out); err != nil { return nil, err }
    return out, api.RetvalToVPPApiError(out.Retval)
}
func (c *serviceClient) TlsctrlVPNTunnelClose(ctx context.Context, in *TlsctrlVPNTunnelClose) (*TlsctrlVPNTunnelCloseReply, error) {
    out := new(TlsctrlVPNTunnelCloseReply)
    if err := c.conn.Invoke(ctx, in, out); err != nil { return nil, err }
    return out, api.RetvalToVPPApiError(out.Retval)
}

type RPCService_TlsctrlVPNPoolDumpClient interface { Recv() (*TlsctrlVPNPoolDetails, error); api.Stream }
type serviceClient_TlsctrlVPNPoolDumpClient struct { api.Stream }
func (c *serviceClient) TlsctrlVPNPoolDump(ctx context.Context, in *TlsctrlVPNPoolDump) (RPCService_TlsctrlVPNPoolDumpClient, error) {
    stream, err := c.conn.NewStream(ctx)
    if err != nil { return nil, err }
    x := &serviceClient_TlsctrlVPNPoolDumpClient{stream}
    if err := x.Stream.SendMsg(in); err != nil { return nil, err }
    if err = x.Stream.SendMsg(&memclnt.ControlPing{}); err != nil { return nil, err }
    return x, nil
}
func (c *serviceClient_TlsctrlVPNPoolDumpClient) Recv() (*TlsctrlVPNPoolDetails, error) {
    msg, err := c.Stream.RecvMsg()
    if err != nil { return nil, err }
    switch m := msg.(type) {
    case *TlsctrlVPNPoolDetails:
        return m, nil
    case *memclnt.ControlPingReply:
        if err = c.Stream.Close(); err != nil { return nil, err }
        return nil, io.EOF
    default:
        return nil, fmt.Errorf("unexpected message: %T %v", m, m)
    }
}

type RPCService_TlsctrlVPNProfileDumpClient interface { Recv() (*TlsctrlVPNProfileDetails, error); api.Stream }
type serviceClient_TlsctrlVPNProfileDumpClient struct { api.Stream }
func (c *serviceClient) TlsctrlVPNProfileDump(ctx context.Context, in *TlsctrlVPNProfileDump) (RPCService_TlsctrlVPNProfileDumpClient, error) {
    stream, err := c.conn.NewStream(ctx)
    if err != nil { return nil, err }
    x := &serviceClient_TlsctrlVPNProfileDumpClient{stream}
    if err := x.Stream.SendMsg(in); err != nil { return nil, err }
    if err = x.Stream.SendMsg(&memclnt.ControlPing{}); err != nil { return nil, err }
    return x, nil
}
func (c *serviceClient_TlsctrlVPNProfileDumpClient) Recv() (*TlsctrlVPNProfileDetails, error) {
    msg, err := c.Stream.RecvMsg()
    if err != nil { return nil, err }
    switch m := msg.(type) {
    case *TlsctrlVPNProfileDetails:
        return m, nil
    case *memclnt.ControlPingReply:
        if err = c.Stream.Close(); err != nil { return nil, err }
        return nil, io.EOF
    default:
        return nil, fmt.Errorf("unexpected message: %T %v", m, m)
    }
}

type RPCService_TlsctrlVPNTunnelDumpClient interface { Recv() (*TlsctrlVPNTunnelDetails, error); api.Stream }
type serviceClient_TlsctrlVPNTunnelDumpClient struct { api.Stream }
func (c *serviceClient) TlsctrlVPNTunnelDump(ctx context.Context, in *TlsctrlVPNTunnelDump) (RPCService_TlsctrlVPNTunnelDumpClient, error) {
    stream, err := c.conn.NewStream(ctx)
    if err != nil { return nil, err }
    x := &serviceClient_TlsctrlVPNTunnelDumpClient{stream}
    if err := x.Stream.SendMsg(in); err != nil { return nil, err }
    if err = x.Stream.SendMsg(&memclnt.ControlPing{}); err != nil { return nil, err }
    return x, nil
}
func (c *serviceClient_TlsctrlVPNTunnelDumpClient) Recv() (*TlsctrlVPNTunnelDetails, error) {
    msg, err := c.Stream.RecvMsg()
    if err != nil { return nil, err }
    switch m := msg.(type) {
    case *TlsctrlVPNTunnelDetails:
        return m, nil
    case *memclnt.ControlPingReply:
        if err = c.Stream.Close(); err != nil { return nil, err }
        return nil, io.EOF
    default:
        return nil, fmt.Errorf("unexpected message: %T %v", m, m)
    }
}
