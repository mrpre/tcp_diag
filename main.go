package main

import (
	"flag"
	"log"
	"github.com/mrpre/tcp_diag/src/namespace"
	"github.com/mrpre/tcp_diag/src/netlink"
	"github.com/mrpre/tcp_diag/src/tcp_diag"
)

func main() {
	var tcpdiaginfo []tcp_diag.TcpDiagInfo
	allNs := flag.Bool("all", false, "--all will show the socket from all namespace")
	flag.Parse()

	//I just use goroutine to test setns, normally goroutine is not necessary
	done := make(chan int)
	go func() {
		if *allNs {
			namespace.ForEachNetNS(nil,
				func(ctx interface{}) error {
					//we are in new net namespace
					h, err := tcp_diag.New()
					if err != nil {
						panic(err)
					}
					if err := h.Dump(&tcpdiaginfo); err != nil {
						panic(err)
					}
					h.Close()
					return nil
				})
		}
		done <- 1
	}()

	<-done
	for _, inf := range tcpdiaginfo {
		Addrs := inf.Data.Id.String()
		if inf.Attrs != nil {
			if attr, ok := inf.Attrs[netlink.INET_DIAG_INFO]; ok {
				tcpinfo, _ := attr.GetTcpInfo()
				//Note only first validSize of tcpinfo is valid because different kernel has it's own TCPInfo struct
				Addrs = tcp_diag.TCP_STATE[tcpinfo.State] + ":" + Addrs
			}
		}
		log.Println(Addrs)
	}

}
