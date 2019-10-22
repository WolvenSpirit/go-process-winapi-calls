package main

import (
	"bufio"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	PROCESS_ALL_ACCESS = 0x1F0FFF
	TH32CS_INHERIT     = 0x80000000
	TH32CS_SNAPPROCESS = 0x00000002
)
const (
	PRIORITY_R_SUCCESS                uint32 = 0
	PRIORITY_R_ACCESS_DENIED          uint32 = 2
	PRIORITY_R_INSUFFICIENT_PRIVILEGE uint32 = 3
	PRIORITY_R_UNKNOWN_FAILURE        uint32 = 8
	PRIORITY_R_PATH_NOT_FOUND         uint32 = 9
	PRIORITY_R_INVALID_PARAMETER      uint32 = 21
	PRIORITY_IDLE                     uint32 = 64
	PRIORITY_BELOW_NORMAL             uint32 = 16384
	PRIORITY_NORMAL                   uint32 = 32
	PRIORITY_ABOVE_NORMAL             uint32 = 32768
	PRIORITY_HIGH_PRIORITY            uint32 = 128
)

var pids map[string]uint32

type dword uint32

var single dword = 1
var octa dword = 255

var dll *syscall.LazyDLL
var getPAM *syscall.LazyProc
var setPAM *syscall.LazyProc

func init() {
	pids = make(map[string]uint32)
	dll = syscall.NewLazyDLL("kernel32.dll")
	getPAM = dll.NewProc("GetProcessAffinityMask")
	setPAM = dll.NewProc("SetProcessAffinityMask")
}

func getProcString(entry *windows.ProcessEntry32) string {
	posIndex := 0
	for {
		if entry.ExeFile[posIndex] == 0 {
			break
		}
		posIndex++
	}
	return syscall.UTF16ToString(entry.ExeFile[:posIndex])
}

var showProcessesTimes int = 0

func showProcesses() {
	var h windows.Handle
	h, e := windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if e != nil {
		log.Println(e.Error())
	}
	defer windows.CloseHandle(h)
	entry := windows.ProcessEntry32{}
	entry.Size = uint32(unsafe.Sizeof(entry))
	if e := windows.Process32First(h, &entry); e != nil {
		log.Println(e.Error())
	}
	log.Println(getProcString(&entry))

	for true {
		if e := windows.Process32Next(h, &entry); e != nil {
			log.Println(e.Error())
			break
		}
		pids[getProcString(&entry)] = entry.ProcessID
		// log.Printf("Name: %s, PID: %d, Threads: %d", getProcString(&entry), entry.ProcessID, entry.Threads)
	}
	log.Println(len(pids), "processes detected.")
	showProcessesTimes++
}

func modProcessPriority(priorityClass uint32, procname string) {
	var pid uint32 = pids[procname]
	if pid > 0 {
		h, e := windows.OpenProcess(PROCESS_ALL_ACCESS, true, pid)
		if e != nil {
			log.Println(e.Error())
			return
		}
		if e = windows.SetPriorityClass(h, priorityClass); e != nil {
			log.Println(e.Error())
		}
		if e = windows.CloseHandle(h); e != nil {
			log.Println(e.Error())
			return
		}
		log.Println("Successfully modified priority of", procname)
	} else {
		return
	}
}

func getAffinity(pid uint32) (dword, dword) {
	h, e := syscall.OpenProcess(PROCESS_ALL_ACCESS, true, pid)
	if e != nil {
		log.Println(e.Error())
	}
	var dwpam dword = 0 // proc aff mask
	var dwsam dword = 0
	r1, _, e := getPAM.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&dwpam)),
		uintptr(unsafe.Pointer(&dwsam)))
	if e != nil {
		log.Println("GetProcessAffinityMask.Call()", e.Error())

	}
	if r1 > 0 { // Call succeded
		log.Printf("pam: %b sam: %b\n", dwpam, dwsam)
	}
	syscall.CloseHandle(h)
	return dwpam, dwsam
}

func setAffinity(pid uint32, pam dword) {
	//dwpam, _ := getAffinity(pid)
	h, e := syscall.OpenProcess(PROCESS_ALL_ACCESS, true, pid)
	if e != nil {
		log.Println(e.Error())
	}
	for true {
		r, _, e := setPAM.Call(
			uintptr(h),
			uintptr(pam)) // DONT CAST TO UNSAFE
		if e != nil {
			log.Println(e.Error())
		}
		if r != 0 {
			log.Println("Process affinity modified, all done, closing in 3 seconds.")
			time.Sleep(time.Second * 3)
			break
		} else {
			log.Println("Failed to restrict, maybe process isn't running yet. Retrying in 3 seconds.")
			time.Sleep(time.Second * 3)
		}
	}
	syscall.Close(h)
}

func chooseProcess(r *bufio.Reader) string {
	var input string
	var e error
	log.Println("Write process name that should have priority restricted and watched.")
	input, e = r.ReadString('\n')
	if e != nil {
		log.Println(e.Error())
	}
	return input
}

func sanitizeInput(input string) string {
	input = strings.Split(input, "\n")[0]
	return strings.TrimSpace(input)
}

func main() {

	go func() {
		for true {
			log.Println("Refreshing running processes list.")
			showProcesses()
			time.Sleep(time.Second * 60)
		}
	}()

	r := bufio.NewReader(os.Stdin)
	processName := chooseProcess(r)
	processName = sanitizeInput(processName)

	if processName != "" {
		if len(pids) < 30 { // not finished fetching processes
			time.Sleep(time.Second * 3)
		}
		modProcessPriority(PRIORITY_IDLE, processName) // priority idle
		log.Println("Selected PID:", pids[processName])
		setAffinity(pids[processName], 2) // affinity one core
		setAffinity(pids["app.exe"], 5)
	}
}
