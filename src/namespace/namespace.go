package namespace

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	PROC_PATH = "/proc"
)

type Process struct {
	PID int
}

type NameSpace struct {
	Process *Process
	Ino     uint64
	Dir     string
	OpenFd  int
}

func (n *NameSpace) String() string {
	return fmt.Sprintf("PID: %d Ino %d", n.Process.PID, n.Ino)
}

func (p *Process) String() string {
	return fmt.Sprintf("PID: %d", p.PID)
}
func SetNetNs(fd int) error {
	return unix.Setns(fd, syscall.CLONE_NEWNET)
}

func GetCurrentNetNSHandler() (int, error) {
	path := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
	return unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
}

func DeleteCurrentNetNSHandler(fd int) {
	unix.Close(fd)
}

func (ns *NameSpace) GetNetNSHandler() (int, error) {
	var err error
	ns.OpenFd, err = unix.Open(ns.Dir, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	return ns.OpenFd, err
}

func (ns *NameSpace) DeleteNetNSHandler() {
	unix.Close(ns.OpenFd)
}

func ReadAllNetNameSpaces() ([]NameSpace, error) {
	var ret []NameSpace
	allProcesses, err := ReadAllProcesses()
	if err != nil {
		return nil, err
	}
	dupId := make(map[uint64]bool, 1)
	for idx, process := range allProcesses {
		netNs := path.Join("/", "proc", strconv.Itoa(process.PID), "ns", "net")
		if dirFile, err := os.Open(netNs); err != nil {
			//process may stoped
			continue
		} else {
			defer dirFile.Close()
			var stat syscall.Stat_t
			if err = syscall.Fstat(int(dirFile.Fd()), &stat); err != nil {
				return nil, err
			}
			if _, ok := dupId[stat.Ino]; ok {
				continue
			}
			dupId[stat.Ino] = true
			ret = append(ret, NameSpace{
				Process: &allProcesses[idx],
				Ino:     stat.Ino,
				Dir:     netNs,
			})
		}
	}
	return ret, nil
}

func ReadAllProcesses() ([]Process, error) {
	var ret []Process
	dirs, err := ioutil.ReadDir(PROC_PATH)
	if err != nil {
		return nil, err
	}
	for _, info := range dirs {
		if !info.IsDir() {
			continue
		} else {
			if num, err := strconv.Atoi(info.Name()); err != nil {
				continue
			} else {
				ret = append(ret, Process{
					PID: num,
				})
			}
		}
	}
	return ret, nil
}

func ForEachNetNS(ctx interface{}, fn func(interface{}) error) {
	allNs, err := ReadAllNetNameSpaces()
	if err != nil {
		panic(err)
	}

	oriNetNS, err := GetCurrentNetNSHandler()
	if err != nil {
		panic(err)
	}
	//make sure calling goroutine allways run on same os trhead
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for _, ns := range allNs {
		if newNs, err := ns.GetNetNSHandler(); err != nil {
			log.Println("can not open", ns.Dir)
		} else {
			if err := SetNetNs(newNs); err == nil {
				if err := fn(ctx); err != nil {
					ns.DeleteNetNSHandler()
					break
				}
			} else {
				log.Println("can not call setns ", ns.Dir, newNs, err)
			}
		}
		ns.DeleteNetNSHandler()
	}

	if err := SetNetNs(oriNetNS); err != nil {
		panic(fmt.Errorf("fail to recover to original ns %v", err))
	}

	DeleteCurrentNetNSHandler(oriNetNS)
}
