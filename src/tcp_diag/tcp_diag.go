//go:build linux

package tcp_diag

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"github.com/mrpre/tcp_diag/src/netlink"
	"unsafe"
)

var TCP_STATE = map[uint8]string{
	1:  "TCP_ESTABLISHED",
	2:  "TCP_SYN_SENT",
	3:  "TCP_SYN_RECV",
	4:  "TCP_FIN_WAIT1",
	5:  "TCP_FIN_WAIT2",
	6:  "TCP_TIME_WAIT",
	7:  "TCP_CLOSE",
	8:  "TCP_CLOSE_WAIT",
	9:  "TCP_LAST_ACK",
	10: "TCP_LISTEN",
	11: "TCP_CLOSING",
	12: "TCP_NEW_SYN_RECV",
	13: "TCP_MAX_STATES",
}
var TCP_STATE_FLAG_ALL uint32 = (1 << 13) - 1

type TcpDiagHandler struct {
	Socket *netlink.NetLinkSocket
}

type TcpDiagInfo struct {
	Data  *netlink.InetDiagMsg
	Attrs map[uint16]netlink.InetDiagAttr
}

func New() (*TcpDiagHandler, error) {
	socket, err := netlink.CreateNetLinkSocket()
	if err != nil {
		return nil, err
	}

	// if we don't set socket nonblock, default RCVBUF is to small to save tcp info and tcpinfo will be dropped
	if true {
		if err := syscall.SetNonblock(socket.Fd, true); err != nil {
			return nil, err
		}
	} else {
		if err := syscall.SetsockoptInt(socket.Fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 32768); err != nil {
			return nil, err
		}

		if err := syscall.SetsockoptInt(socket.Fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1048576); err != nil {
			return nil, err
		}
	}
	return &TcpDiagHandler{
		Socket: socket,
	}, nil
}

func (h *TcpDiagHandler) Close() {
	netlink.DestoryNetLinkSocket(h.Socket)
}

func (h *TcpDiagHandler) Dump(infos *[]TcpDiagInfo) error {
	req := &netlink.NetlinkRequest{
		Nlh: syscall.NlMsghdr{
			Len:   uint32(0), //filled by req.Serialize
			Type:  uint16(netlink.SOCK_DIAG_BY_FAMILY),
			Flags: uint16(syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST),
			Seq:   uint32(0),
			Pid:   uint32(os.Getpid()),
		},
		//v2 with SOCK_DIAG_BY_FAMILY
		//v1 with TCPDIAG_GETSOCK
		Data: *netlink.NewInetDiagReqV2(syscall.AF_INET, syscall.IPPROTO_TCP, TCP_STATE_FLAG_ALL),
	}
	err := h.Socket.Send(req)
	if err != nil {
		return err
	}

	/*
		syscall.NetlinkRecvMsg(h.Socket.Fd, func(responses []syscall.NetlinkMessage) {
			for _, msg := range responses {
				if msg.Header.Type == syscall.NLMSG_ERROR {
					panic("err")
				} else if msg.Header.Type == syscall.NLMSG_DONE {
					return
				} else {
					data := netlink.ParseInetDiagMsg(msg.Data)
					//log.Println("family", data.IDiagFamily, "msg.Header.Len", msg.Header.Len, "data buf len", len(msg.Data))

					_, err := netlink.ParseInetDiagAttr(&msg)
					if err != nil {
						log.Println("fail to get attr from tcp_diag", err, msg.Header.Type)
					}
					fmt.Println(data.Id.String(), data.IDiagUid, data.IDiagInode)

				}
			}
		})
		return nil
	*/
	responses, err := h.Socket.Receive()
	if err != nil {
		return err
	}
	//log.Println("total get ", len(responses))
	for _, msg := range responses {
		if msg.Header.Type == syscall.NLMSG_ERROR {
			msgerr := (*syscall.NlMsgerr)(unsafe.Pointer(&msg.Data[0]))

			return fmt.Errorf("netlink returned error message with error code %d: %s",
				-msgerr.Error,
				syscall.Errno(-msgerr.Error).Error())

		} else if msg.Header.Type == syscall.NLMSG_DONE {
			return nil
		} else {
			data := netlink.ParseInetDiagMsg(msg.Data)
			attr, err := netlink.ParseInetDiagAttr(&msg)
			if err != nil {
				log.Println("fail to get attr from tcp_diag", err, msg.Header.Type)
			}
			*infos = append(*infos, TcpDiagInfo{
				Data:  data,
				Attrs: attr,
			})
			//fmt.Println(data.Id.String())
		}
	}
	return nil
}
