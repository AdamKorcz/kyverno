package pss

import (
	"encoding/json"
	//"fmt"
	"reflect"
	"testing"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	//"gotest.tools/assert"
	corev1 "k8s.io/api/core/v1"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	"golang.org/x/exp/slices"
)

var (
	allowedCapabilities = []corev1.Capability{"AUDIT_WRITE",
		"CHOWN",
		"DAC_OVERRIDE",
		"FOWNER",
		"FSETID",
		"KILL",
		"MKNOD",
		"NET_BIND_SERVICE",
		"SETFCAP",
		"SETGID",
		"SETPCAP",
		"SETUID",
		"SYS_CHROOT"}
	allowedSELinuxTypes = []string{"container_t",
		"container_init_t",
		"container_kvm_t",
		""}
	allowed_sysctls = []string{
		"kernel.shm_rmid_forced",
		"net.ipv4.ip_local_port_range",
		"net.ipv4.ip_unprivileged_port_start",
		"net.ipv4.tcp_syncookies",
		"net.ipv4.ping_group_range",
	}
	baselineOnlyPolicy = []byte(`
		{
			"level": "baseline",
			"version": "v1.24"
		}`)
)

func shouldBlockSELinuxUser(opts *corev1.SELinuxOptions) bool {

	// Check SELinux User. Must be nil/undefined or ""
	fieldName := "User"
	value := reflect.ValueOf(opts)
	field := value.Elem().FieldByName(fieldName)

	if field.IsValid() {
		seLinuxUser := opts.User
		if seLinuxUser != "" {
			return true
		}
	}
	return false
}

func shouldBlockSELinuxRole(opts *corev1.SELinuxOptions) bool {

	// Check SELinux Role. Must be nil/undefined or ""
	fieldName := "Role"
	value := reflect.ValueOf(opts)
	field := value.Elem().FieldByName(fieldName)

	if field.IsValid() {
		seLinuxUser := opts.Role
		if seLinuxUser != "" {
			return true
		}
	}
	return false
}

// return true if pod should be allowed
func shouldAllowBaseline(pod *corev1.Pod) (bool, error) {
	/*if pod.Spec == nil {
		return true, nil
	}*/
	spec := pod.Spec

	/////////////////////////////
	///// Check Container-related properties /////
	/////////////////////////////
	if spec.SecurityContext != nil {
		sc := spec.SecurityContext
		// Check host process. Must be nil or false
		if sc.WindowsOptions != nil {
			if sc.WindowsOptions.HostProcess != nil {
				if *sc.WindowsOptions.HostProcess == true {
					return false, nil
				}
			}
		}

		if shouldBlockSELinuxUser(sc.SELinuxOptions) {
			return false, nil
		}

		if shouldBlockSELinuxRole(sc.SELinuxOptions) {
			return false, nil
		}

		// spec.securityContext.seccompProfile.type
		// Check Seccomp
		if sc.SeccompProfile != nil {
			seccompType := sc.SeccompProfile.Type
			defaultSeccomp := corev1.SeccompProfileTypeRuntimeDefault
			localhostSeccomp := corev1.SeccompProfileTypeLocalhost
			if seccompType != defaultSeccomp && seccompType != localhostSeccomp {
				return false, nil
			}
		}
		// spec.securityContext.sysctls[*].name
		fieldName := "Sysctls"
		value := reflect.ValueOf(sc)
		field := value.FieldByName(fieldName)

		if field.IsValid() {
			for _, sysctl := range sc.Sysctls {
				if !slices.Contains(allowed_sysctls, sysctl.Name) {

				}
			}
		}
	}

	if pod.Spec.Containers != nil || len(pod.Spec.Containers) != 0 {

		containers := pod.Spec.Containers
		for _, container := range containers {
			// Check host process. Must be nil or false
			if container.SecurityContext != nil {
				if shouldBlockContainerSecurityContext(container.SecurityContext) {
					return false, nil
				}
			}

			// Check container ports. Must be nil or 0
			fieldName := "Ports"
			value := reflect.ValueOf(container)
			field := value.FieldByName(fieldName)
			if field.IsValid() {
				if shouldBlockContainerPorts(container.Ports) {
					return false, nil
				}
			}
		}
	}

	if pod.Spec.InitContainers != nil || len(pod.Spec.InitContainers) != 0 {

		containers := pod.Spec.InitContainers
		for _, container := range containers {
			// Check host process. Must be nil or false
			if container.SecurityContext != nil {
				if shouldBlockContainerSecurityContext(container.SecurityContext) {
					return false, nil
				}
			}

			// Check container ports. Must be nil or 0
			fieldName := "Ports"
			value := reflect.ValueOf(container)
			field := value.FieldByName(fieldName)
			if field.IsValid() {
				if shouldBlockContainerPorts(container.Ports) {
					return false, nil
				}
			}
		}
	}

	if pod.Spec.EphemeralContainers != nil || len(pod.Spec.EphemeralContainers) != 0 {
		containers := pod.Spec.EphemeralContainers
		for _, container := range containers {
			// Check host process. Must be nil or false
			if container.SecurityContext != nil {
				if shouldBlockContainerSecurityContext(container.SecurityContext) {
					return false, nil
				}
			}

			// Check container ports. Must be nil or 0
			fieldName := "Ports"
			value := reflect.ValueOf(container)
			field := value.FieldByName(fieldName)
			if field.IsValid() {
				if shouldBlockContainerPorts(container.Ports) {
					return false, nil
				}
			}
		}
	}

	////////////////////////////////////7
	// Host Namespaces
	if spec.SecurityContext != nil {
		fieldName := "HostNetwork"
		value := reflect.ValueOf(spec)
		field := value.FieldByName(fieldName)

		if field.IsValid() {
			if spec.HostNetwork == true {
				return false, nil
			}
		}

		fieldName = "HostPID"
		field = value.FieldByName(fieldName)

		if field.IsValid() {
			if spec.HostPID == true {
				return false, nil
			}
		}

		fieldName = "HostIPC"
		field = value.FieldByName(fieldName)

		if field.IsValid() {
			if spec.HostIPC == true {
				return false, nil
			}
		}
	}
	return true, nil
}

func shouldBlockContainerSecurityContext(sc *corev1.SecurityContext) bool {
	if sc.WindowsOptions != nil {
		if sc.WindowsOptions.HostProcess != nil {
			if *sc.WindowsOptions.HostProcess == true {
				return true
			}
		}
	}
	// Check privileged. Must be nil or false
	if sc.Privileged != nil {
		if *sc.Privileged == false {
			return true
		}
	}

	// Check capabilities
	if sc.Capabilities != nil {
		capabilities := sc.Capabilities

		if shouldBlockBaselineCapabilities(capabilities) {
			return true
		}
	}

	// Check SELinux.
	if sc.SELinuxOptions != nil {
		seLinuxOptions := sc.SELinuxOptions
		if shouldBlockContainerSELinux(seLinuxOptions) {
			return true
		}
	}

	// Check /proc / Mount Type
	if sc.ProcMount != nil {
		if *sc.ProcMount != corev1.DefaultProcMount {
			return true
		}
	}

	// Check Seccomp
	if sc.SeccompProfile != nil {
		seccompType := sc.SeccompProfile.Type
		defaultSeccomp := corev1.SeccompProfileTypeRuntimeDefault
		localhostSeccomp := corev1.SeccompProfileTypeLocalhost
		if seccompType != defaultSeccomp && seccompType != localhostSeccomp {
			return true
		}
	}

	return false
}

func shouldBlockContainerSELinux(opts *corev1.SELinuxOptions) bool {
	// Check SELinux Type. Must be allowed value or nil/undefined or ""
	fieldName := "Type"
	value := reflect.ValueOf(opts)
	field := value.FieldByName(fieldName)

	if field.IsValid() {
		seLinuxType := opts.Type
		if !slices.Contains(allowedSELinuxTypes, seLinuxType) {
			return true
		}
	}

	if shouldBlockSELinuxUser(opts) {
		return true
	}

	if shouldBlockSELinuxRole(opts) {
		return true
	}

	return false
}

func shouldBlockContainerPorts(ports []corev1.ContainerPort) bool {
	if len(ports) > 0 {
		for _, port := range ports {

			fieldName := "HostPort"
			value := reflect.ValueOf(port)
			field := value.FieldByName(fieldName)

			if field.IsValid() {
				if port.HostPort != 0 {
					return true
				}
			}
		}
	}
	return false
}

func shouldBlockBaselineCapabilities(capabilities *corev1.Capabilities) (bool) {
	fieldName := "Add"
	value := reflect.ValueOf(capabilities)
	field := value.FieldByName(fieldName)

	if field.IsValid() {
		if len(capabilities.Add) > 0 {
			for _, capability := range capabilities.Add {
				for _, allowedCapability := range allowedCapabilities {
					if capability != allowedCapability {
						return true
					}
				}
			}
		}
	}
	return false
}

func getPod(ff *fuzz.ConsumeFuzzer) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	err := ff.GenerateStruct(pod)
	pod.Kind = "Pod"
	pod.APIVersion = "v1"
	return pod, err
}

func FuzzBaselinePS(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {

		ff := fuzz.NewConsumer(data)
		/*policyToCheck, err := ff.GetInt()
		if err != nil {
			return
		}*/

		pod, err := getPod(ff)
		if err != nil {
			return
		}

		var allowPod bool
		allowPod, _ = shouldAllowBaseline(pod)
		if allowPod { return }

		var rule kyvernov1.PodSecurity
		err = json.Unmarshal(baselineOnlyPolicy, &rule)
		if err != nil {
			panic(err)
		}

		allowed, _, _ := EvaluatePod(&rule, pod)
		if allowPod != allowed {
			panic("They don't correlate")
		}
	})
}
