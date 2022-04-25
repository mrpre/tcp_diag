package netlink

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"unsafe"
)

const (
	SizeofInetDiagReqV2 = 0x38
)

const (
	TCPDIAG_GETSOCK     = 18 // linux/inet_diag.h
	SOCK_DIAG_BY_FAMILY = 20 // linux/sock_diag.h
)

type be16 [2]byte
type be32 [4]byte

type NetLinkSocket struct {
	Fd   int
	Addr *syscall.SockaddrNetlink
}

/*
linux/inet_diag.h
struct inet_diag_sockid {
	__be16	idiag_sport;
	__be16	idiag_dport;
	__be32	idiag_src[4];
	__be32	idiag_dst[4];
	__u32	idiag_if;
	__u32	idiag_cookie[2];
#define INET_DIAG_NOCOOKIE (~0U)
};
*/
type InetDiagSockId struct {
	IDiagSPort  uint16  //network order
	IDiagDPort  uint16  //network order
	IDiagSrc    [4]be32 //for ipv4 only index 0 is used
	IDiagDst    [4]be32 //for ipv4 only index 0 is used
	IDiagIf     uint32
	IDiagCookie [2]uint32
}

func (id *InetDiagSockId) SrcIPv4() net.IP {
	srcip := id.IDiagSrc[0]
	return net.IPv4(srcip[0], srcip[1], srcip[2], srcip[3])
}

func (id *InetDiagSockId) DstIPv4() net.IP {
	dstip := id.IDiagDst[0]
	return net.IPv4(dstip[0], dstip[1], dstip[2], dstip[3])
}

func ntohs(p uint16) uint16 {
	return ((p & 0xFF) << 8) | (p >> 8)
}

func (id *InetDiagSockId) String() string {
	return fmt.Sprintf("%s:%d-> %s:%d", id.SrcIPv4().String(), ntohs(id.IDiagSPort), id.DstIPv4().String(), ntohs(id.IDiagDPort))
}

/*
linux/inet_diag.h
struct inet_diag_req_v2 {
	__u8	sdiag_family;
	__u8	sdiag_protocol;
	__u8	idiag_ext;
	__u8	pad;
	__u32	idiag_states;
	struct inet_diag_sockid id;
};
*/
type InetDiagReqV2 struct {
	SDiagFamily   uint8
	SDiagProtocol uint8
	IDiagExt      uint8
	Pad           uint8
	IDiagStates   uint32
	Id            InetDiagSockId
}

/*
linux/inet_diag.h
enum {
	INET_DIAG_NONE,
	INET_DIAG_MEMINFO,
	INET_DIAG_INFO,
	INET_DIAG_VEGASINFO,
	INET_DIAG_CONG,
	INET_DIAG_TOS,
	INET_DIAG_TCLASS,
	INET_DIAG_SKMEMINFO,
	INET_DIAG_SHUTDOWN,

	 Next extenstions cannot be requested in struct inet_diag_req_v2:
	its field idiag_ext has only 8 bits.

	 INET_DIAG_DCTCPINFO,	request as INET_DIAG_VEGASINFO
	 INET_DIAG_PROTOCOL,	response attribute only
	 INET_DIAG_SKV6ONLY,
	 INET_DIAG_LOCALS,
	 INET_DIAG_PEERS,
	 INET_DIAG_PAD,
	 INET_DIAG_MARK,		only with CAP_NET_ADMIN
	 INET_DIAG_BBRINFO,	    request as INET_DIAG_VEGASINFO
	 INET_DIAG_CLASS_ID,	request as INET_DIAG_TCLASS
	 INET_DIAG_MD5SIG,
	 __INET_DIAG_MAX,
};
*/

var (
	INET_DIAG_NONE      uint16 = 0
	INET_DIAG_MEMINFO   uint16 = 1
	INET_DIAG_INFO      uint16 = 2
	INET_DIAG_VEGASINFO uint16 = 3
	INET_DIAG_CONG      uint16 = 4
	INET_DIAG_TOS       uint16 = 5
	INET_DIAG_TCLASS    uint16 = 6
	INET_DIAG_SKMEMINFO uint16 = 7
	INET_DIAG_SHUTDOWN  uint16 = 8

	INET_DIAG_MEMINFO_FLAG   uint8 = 1 << (INET_DIAG_MEMINFO - 1)
	INET_DIAG_INFO_FLAG      uint8 = 1 << (INET_DIAG_INFO - 1)
	INET_DIAG_VEGASINFO_FLAG uint8 = 1 << (INET_DIAG_VEGASINFO - 1)
	INET_DIAG_CONG_FLAG      uint8 = 1 << (INET_DIAG_CONG - 1)
	INET_DIAG_SKMEMINFO_FLAG uint8 = 1 << (INET_DIAG_SKMEMINFO - 1)

	//our use
	CUSTOM_TCPINFO_FLAG = INET_DIAG_INFO_FLAG | INET_DIAG_VEGASINFO_FLAG | INET_DIAG_CONG_FLAG
)

func NewInetDiagReqV2(family, protocol uint8, states uint32) *InetDiagReqV2 {
	return &InetDiagReqV2{
		SDiagFamily:   family,
		SDiagProtocol: protocol,
		//IDiagExt:      0,
		IDiagExt:    CUSTOM_TCPINFO_FLAG,
		IDiagStates: states,
	}
}

// request must be combined like this
type NetlinkRequest struct {
	Nlh syscall.NlMsghdr
	//Datas []NetlinkRequestData
	Data InetDiagReqV2
}

/*
   struct
   {
       struct nlmsghdr nlh;
       struct inet_diag_req r;
   } req;
*/
func (req *NetlinkRequest) Serialize() []byte {
	//const hdrLen = int(unsafe.Sizeof(NetlinkRequest{}.nlh))
	const hdrLen = syscall.SizeofNlMsghdr
	const DataLen = int(unsafe.Sizeof(req.Data))
	dataBytes := make([]byte, hdrLen+DataLen)

	req.Nlh.Len = uint32(DataLen + hdrLen)
	hdr := (*(*[syscall.SizeofNlMsghdr]byte)(unsafe.Pointer(&req.Nlh)))[:]

	var data []byte = (*(*[DataLen]byte)(unsafe.Pointer(&req.Data)))[:]
	copy(dataBytes[0:hdrLen], hdr)
	copy(dataBytes[hdrLen:hdrLen+DataLen], data)

	return dataBytes
}

func DestoryNetLinkSocket(socket *NetLinkSocket) {
	syscall.Close(socket.Fd)
}

func CreateNetLinkSocket() (*NetLinkSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW,
		syscall.NETLINK_INET_DIAG)
	if err != nil {
		return nil, err
	}

	sockaddr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    0,
		Groups: 0,
	}

	return &NetLinkSocket{
		Fd:   fd,
		Addr: sockaddr,
	}, nil
}

func (s *NetLinkSocket) Send(request *NetlinkRequest) error {

	if err := syscall.Sendto(s.Fd, request.Serialize(), 0, s.Addr); err != nil {
		return err
	}

	return nil
}

func netlinkRecv(fd int, rb []byte, flags int) (int, error) {
	for {
		len, _, err := syscall.Recvfrom(fd, rb, flags)
		//if caller parse the message once netlinkRecv return a byte
		//because caller can stop call recv once NLMSG_DONE is parsed
		//so following code can be used.
		//if len < 0 && (err == syscall.EINTR || err == syscall.EAGAIN) {
		//	continue
		//}
		//but now caller just try to recv all data with parsing, because tcp_diag has send the data
		//when diag_request is sent by sendto so that if no data is returned it means we recvived all data.
		//
		if len < 0 && err == syscall.EAGAIN {
			return 0, nil
		}
		if len < 0 {
			log.Println("netlink Recvfrom err err", err)
			return len, err
		}
		if len == 0 {
			log.Println("netlink Recvfrom EOF", err)
			return len, syscall.ENODATA
		}
		return len, nil
	}
}

//we should parse data message in recv
func (s *NetLinkSocket) ReceiveMulti() ([]syscall.NetlinkMessage, error) {
	//rb := make([]byte, syscall.Getpagesize()*1000)
	var rbTotal []byte
	//var nrTotal = 0

	//if peek is not used, kernel just copy size of rb to rb then drop the skb
	//we should know actual length of current size of skb
	for {
		var rb []byte
		//MSG_TRUNC tell the kernel the true return size
		size, err := netlinkRecv(s.Fd, rb, syscall.MSG_PEEK|syscall.MSG_TRUNC)
		//log.Println("data size", size)
		if err != nil {
			return nil, err
		}
		if size == 0 {
			break
		}
		rb = make([]byte, size)
		size, err = netlinkRecv(s.Fd, rb, 0)
		if err != nil {
			return nil, err
		}
		rb = rb[:size]
		rbTotal = append(rbTotal, rb...)
	}
	/*
		struct nlmsghdr {
			__u32		nlmsg_len;	 Length of message including header
			__u16		nlmsg_type;	 Message content
			__u16		nlmsg_flags; Additional flags
			__u32		nlmsg_seq;	 Sequence number
			__u32		nlmsg_pid;	 Sending process port ID
		};

		data[]
	*/
	//log.Println("rbTotal", len(rbTotal), rbTotal)
	return syscall.ParseNetlinkMessage(rbTotal)
}

func (s *NetLinkSocket) Receive() ([]syscall.NetlinkMessage, error) {
	return s.ReceiveMulti()
}

/*
linux/inet_diag.h
struct inet_diag_msg {
	__u8	idiag_family;
	__u8	idiag_state;
	__u8	idiag_timer;
	__u8	idiag_retrans;

	struct inet_diag_sockid id;

	__u32	idiag_expires;
	__u32	idiag_rqueue;
	__u32	idiag_wqueue;
	__u32	idiag_uid;
	__u32	idiag_inode;
};
*/
type InetDiagMsg struct {
	IDiagFamily  uint8
	IDiagState   uint8
	IDiagTimer   uint8
	IDiagRetrans uint8
	Id           InetDiagSockId
	IDiagExpires uint32
	IDiagRqueue  uint32
	IDiagWqueue  uint32
	IDiagUid     uint32
	IDiagInode   uint32
}

func ParseInetDiagMsg(data []byte) *InetDiagMsg {
	return (*InetDiagMsg)(unsafe.Pointer(&data[0]))
}

type InetDiagAttr struct {
	ID   uint16
	Val  interface{}
	Size uint16
}

func (attr *InetDiagAttr) GetTcpInfo() (*syscall.TCPInfo, uint16) {
	return attr.Val.(*syscall.TCPInfo), attr.Size
}

func parseTcpInfoTcpInfo(attrData []byte) interface{} {
	if len(attrData) < syscall.SizeofTCPInfo {
		panic(fmt.Errorf("tcp info size from netlink is %d, different from syscall.SizeofTCPInfo %d", len(attrData), syscall.SizeofTCPInfo))
	}

	return (*syscall.TCPInfo)(unsafe.Pointer(&attrData[0]))
}

func ParseInetDiagAttr(msg *syscall.NetlinkMessage) (map[uint16]InetDiagAttr, error) {
	ret := make(map[uint16]InetDiagAttr)
	dataSize := uint32(unsafe.Sizeof(InetDiagMsg{}))

	//msg.Header.Len include the Header size itself
	attrSize := uint16(msg.Header.Len - dataSize - syscall.NLMSG_HDRLEN)
	//fmt.Println("fixed dataSize", dataSize, "attrsize", attrSize, "total buf size", len(msg.Data))
	if attrSize == 0 {
		return ret, nil
	}
	rawAttrs := msg.Data[dataSize:]
	/* /use/include/linux/netlink.h
	 *  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
	 * +---------------------+- - -+- - - - - - - - - -+- - -+
	 * |        Header       | Pad |     Payload       | Pad |
	 * |   (struct nlattr)   | ing |                   | ing |
	 * +---------------------+- - -+- - - - - - - - - -+- - -+
	 *  <-------------- nlattr->nla_len -------------->
	 */

	//#define RTA_ALIGN(len) ( ((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1) )
	var NLA_ALIGN = func(size uint16, alignto uint16) uint16 {
		return (((size) + alignto - 1) & ^(alignto - 1))
	}
	var idx uint16
	for idx = 0; idx < attrSize; {
		rawAttr := rawAttrs[idx:]
		attr := (*syscall.NlAttr)(unsafe.Pointer(&rawAttr[0]))

		//out of bound
		if idx+syscall.NLA_HDRLEN > attrSize {
			panic(fmt.Errorf("attr size error"))
		}
		attrDataSize := attr.Len - syscall.NLA_HDRLEN
		//fmt.Println("idx", idx, "attr ", *attr, "attrDataSize", attrDataSize, "len(rawAttr)", len(rawAttr))

		if attrDataSize == 0 {
			idx += syscall.NLA_HDRLEN
			continue
		}

		//fmt.Println("start", idx+syscall.NLA_HDRLEN, "end ", idx+syscall.NLA_HDRLEN+attrDataSize)
		attrData := rawAttr[syscall.NLA_HDRLEN : syscall.NLA_HDRLEN+attrDataSize]

		switch attr.Type {
		case INET_DIAG_MEMINFO:
		case INET_DIAG_INFO:
			tcpinfo := parseTcpInfoTcpInfo(attrData)
			ret[INET_DIAG_INFO] = InetDiagAttr{INET_DIAG_INFO, tcpinfo, uint16(len(attrData))}
		case INET_DIAG_VEGASINFO:
		case INET_DIAG_CONG:
		case INET_DIAG_TOS:
		case INET_DIAG_TCLASS:
		case INET_DIAG_SKMEMINFO:
		case INET_DIAG_SHUTDOWN:

		default:
			break
		}
		idx += NLA_ALIGN(attr.Len, syscall.NLA_ALIGNTO)
	}

	if idx != attrSize {
		panic(fmt.Errorf("size err"))
	}

	//fmt.Println("data size", dataSize, msg.Data)
	return ret, nil
}
