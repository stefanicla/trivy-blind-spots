# METADATA
# title: Docker Compose service hardening
# description: Trivy has no built-in Docker Compose checks. This custom check flags the most dangerous Compose settings.
# scope: package
# schemas:
#   - input: schema["yaml"]
# custom:
#   id: CMP-0001
#   avd_id: CMP-0001
#   provider: compose
#   service: docker-compose
#   severity: HIGH
#   short_code: compose-hardening
#   recommended_action: Remove privileged mode, host namespaces, Docker socket mounts and added capabilities; do not hard-code credentials.
#   input:
#     selector:
#       - type: yaml
package user.compose.hardening

import rego.v1

# Only Compose files have a top-level "services" map whose entries carry an image or build.
services contains [name, svc] if {
	some name, svc in input.services
	is_object(svc)
	some key in {"image", "build"}
	svc[key]
}

deny contains msg if {
	some [name, svc] in services
	svc.privileged == true
	msg := sprintf("Service '%s' runs in privileged mode", [name])
}

deny contains msg if {
	some [name, svc] in services
	some ns in {"network_mode", "pid", "ipc"}
	svc[ns] == "host"
	msg := sprintf("Service '%s' shares the host %s namespace", [name, ns])
}

deny contains msg if {
	some [name, svc] in services
	some vol in svc.volumes
	contains(sprintf("%v", [vol]), "docker.sock")
	msg := sprintf("Service '%s' mounts the Docker socket", [name])
}

deny contains msg if {
	some [name, svc] in services
	some cap in svc.cap_add
	upper(cap) in {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"}
	msg := sprintf("Service '%s' adds the dangerous capability %s", [name, cap])
}

deny contains msg if {
	some [name, svc] in services
	svc.user in {"root", "0", "0:0"}
	msg := sprintf("Service '%s' runs as root", [name])
}

deny contains msg if {
	some [name, svc] in services
	some key, value in svc.environment
	regex.match(`(?i)(password|passwd|secret|token|api_?key)`, key)
	is_string(value)
	not startswith(value, "${")
	msg := sprintf("Service '%s' hard-codes a credential in environment variable %s", [name, key])
}

deny contains msg if {
	some [name, svc] in services
	endswith(svc.image, ":latest")
	msg := sprintf("Service '%s' uses the ':latest' image tag", [name])
}
