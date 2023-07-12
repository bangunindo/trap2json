package snmp

import (
	"github.com/pkg/errors"
	"github.com/sleepinggenius2/gosmi"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
)

const mibDefaultPath = "/usr/share/snmp/mibs"

var mibInit = false
var mibInitLock = new(sync.Mutex)

type mibPaths struct {
	dirs    []string
	modules []string
}

// gosmi somehow failed to load these built-in modules, excluding them to supress
// warning logs
var excludedModules = map[string]bool{
	"DPI20-MIB":  true,
	"HPR-MIB":    true,
	"SNMPv2-PDU": true,
	"TCPIPX-MIB": true,
}

func getMibFiles(path string) (mibPaths, error) {
	var paths mibPaths
	if err := filepath.WalkDir(
		path,
		func(path string, d fs.DirEntry, err error) error {
			if err == nil {
				if d.IsDir() {
					paths.dirs = append(paths.dirs, path)
				} else if d.Type()&fs.ModeSymlink != 0 {
					if path, err = filepath.EvalSymlinks(path); err == nil {
						p, err := getMibFiles(path)
						if err != nil {
							return err
						}
						paths.dirs = append(paths.dirs, p.dirs...)
						paths.modules = append(paths.modules, p.modules...)
					}
				} else {
					paths.modules = append(paths.modules, strings.Split(d.Name(), ".")[0])
				}
			}
			return nil
		}); err != nil {
		return paths, err
	}
	return paths, nil
}

func InitMIBTranslator(mibPath string) ([]string, error) {
	mibInitLock.Lock()
	defer mibInitLock.Unlock()
	if mibInit {
		return nil, nil
	}
	var failedModules []string
	var succeededModules []string
	gosmi.Init()
	for _, path := range []string{mibDefaultPath, mibPath} {
		mibFiles, err := getMibFiles(path)
		if err != nil {
			return succeededModules, err
		}
		for _, path := range mibFiles.dirs {
			gosmi.AppendPath(path)
		}
		for _, module := range mibFiles.modules {
			if ok := excludedModules[module]; ok {
				continue
			}
			if _, err := gosmi.GetModule(module); err != nil {
				failedModules = append(failedModules, module)
			} else {
				succeededModules = append(succeededModules, module)
			}
		}
	}
	mibInit = true
	if len(failedModules) > 0 {
		return succeededModules, errors.Errorf("some modules failed to load: %s", strings.Join(failedModules, ", "))
	}
	return succeededModules, nil
}
