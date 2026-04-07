//go:build !linux

package system

func ListInstalledApps() ([]string, error) {
	return nil, nil
}

func ListPolicyAppNames() ([]string, error) {
	procs, err := ListProcesses()
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(procs))
	for _, p := range procs {
		if p.Name == "" {
			continue
		}
		if _, ok := seen[p.Name]; ok {
			continue
		}
		seen[p.Name] = struct{}{}
		out = append(out, p.Name)
	}
	return out, nil
}
