package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Runtime struct {
	objects agentguardianObjects
	links   []link.Link
	reader  *ringbuf.Reader
}

func Load() (*Runtime, error) {
	rt := &Runtime{}

	if err := loadAgentguardianObjects(&rt.objects, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	links, err := attachPrograms(&rt.objects)
	if err != nil {
		_ = rt.objects.Close()
		return nil, fmt.Errorf("attaching programs: %w", err)
	}
	rt.links = links

	reader, err := ringbuf.NewReader(rt.objects.Events)
	if err != nil {
		closeLinks(rt.links)
		_ = rt.objects.Close()
		return nil, fmt.Errorf("opening ringbuf: %w", err)
	}
	rt.reader = reader

	return rt, nil
}

func (rt *Runtime) Close() error {
	var errs []error

	if rt.reader != nil {
		errs = append(errs, closeReader(rt.reader))
		rt.reader = nil
	}

	errs = append(errs, closeLinks(rt.links))
	rt.links = nil
	errs = append(errs, rt.objects.Close())

	return errors.Join(errs...)
}

func (rt *Runtime) StopReading() error {
	if rt.reader == nil {
		return nil
	}

	return closeReader(rt.reader)
}

func (rt *Runtime) PolicyMap() *cebpf.Map {
	return rt.objects.PolicyMap
}

func (rt *Runtime) CommPolicyMap() *cebpf.Map {
	return rt.objects.CommPolicyMap
}

func (rt *Runtime) ReadEvent() (Event, error) {
	record, err := rt.reader.Read()
	if err != nil {
		return Event{}, err
	}

	var event Event
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return Event{}, fmt.Errorf("decoding event: %w", err)
	}

	return event, nil
}

func IsClosed(err error) bool {
	return errors.Is(err, ringbuf.ErrClosed)
}

func attachPrograms(objects *agentguardianObjects) ([]link.Link, error) {
	var links []link.Link

	tracepoints := []struct {
		group    string
		name     string
		prog     *cebpf.Program
		optional bool
	}{
		{"syscalls", "sys_enter_openat", objects.HandleOpenatEnter, false},
		{"syscalls", "sys_exit_openat", objects.HandleOpenatExit, false},
		{"syscalls", "sys_enter_openat2", objects.HandleOpenat2Enter, true},
		{"syscalls", "sys_exit_openat2", objects.HandleOpenat2Exit, true},
		{"syscalls", "sys_enter_read", objects.HandleReadEnter, false},
		{"syscalls", "sys_exit_read", objects.HandleReadExit, false},
		{"syscalls", "sys_enter_close", objects.HandleCloseEnter, false},
		{"syscalls", "sys_exit_close", objects.HandleCloseExit, false},
	}

	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			if tp.optional {
				log.Printf("skipping optional tracepoint %s/%s: %v", tp.group, tp.name, err)
				continue
			}
			closeLinks(links)
			return nil, err
		}
		links = append(links, l)
	}

	lsmLink, err := link.AttachLSM(link.LSMOptions{Program: objects.EnforceFileOpen})
	if err != nil {
		log.Printf("lsm/file_open unavailable, hide action disabled: %v", err)
		return links, nil
	}

	links = append(links, lsmLink)
	return links, nil
}

func closeLinks(links []link.Link) error {
	var errs []error
	for _, l := range links {
		errs = append(errs, l.Close())
	}
	return errors.Join(errs...)
}

func closeReader(reader *ringbuf.Reader) error {
	err := reader.Close()
	if err == nil || errors.Is(err, ringbuf.ErrClosed) {
		return nil
	}
	return err
}
