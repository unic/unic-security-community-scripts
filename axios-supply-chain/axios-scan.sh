#!/usr/bin/env bash
# axios-scan.sh — Scan for compromised axios versions (axios supply-chain attack, 2026-03-30)
# Affected: axios@1.14.1, axios@0.30.4 | Malicious dep: plain-crypto-js@4.2.1
# Safe versions: axios@1.14.0 (1.x branch), axios@0.30.3 (0.x branch)

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

AFFECTED_AXIOS=("1.14.1" "0.30.4")
C2_DOMAIN="sfrclak.com"
C2_IP="142.11.206.73"
SCAN_ROOT="${HOME}"

FOUND_AFFECTED=0
FOUND_RAT=0

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║     axios Supply-Chain Attack Scanner (2026-03-30)   ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "    Scanning: ${SCAN_ROOT}${RESET}"
echo ""

# ─── Helpers ───────────────────────────────────────────────────────────────────

is_affected_axios_version() {
	local version="$1"
	for v in "${AFFECTED_AXIOS[@]}"; do
		[[ "$version" == "$v" ]] && return 0
	done
	return 1
}

# Returns "pnpm", "yarn", or "npm" based on lock files present in the project dir.
# Falls back to whichever binary is available if no lock file found.
detect_package_manager() {
	local dir="$1"
	if [[ -f "${dir}/pnpm-lock.yaml" ]]; then
		echo "pnpm"
	elif [[ -f "${dir}/yarn.lock" ]]; then
		echo "yarn"
	elif [[ -f "${dir}/package-lock.json" ]]; then
		echo "npm"
	elif command -v pnpm &>/dev/null; then
		echo "pnpm"
	elif command -v yarn &>/dev/null; then
		echo "yarn"
	else
		echo "npm"
	fi
}

inject_overrides() {
	local pkg_file="$1"
	local branch="$2"    # "0.x" → safe version 0.30.3; any other value defaults to 1.14.0
	local safe_version
	safe_version=$( [[ "$branch" == "0.x" ]] && echo "0.30.3" || echo "1.14.0" )

	if ! command -v jq &>/dev/null; then
		echo -e "  ${YELLOW}[i] jq not found — add overrides manually to ${pkg_file}:${RESET}"
		echo -e '      "overrides": { "axios": "'"${safe_version}"'" }'
		return
	fi

	# Check if overrides.axios is already set correctly
	local existing
	if ! existing=$(jq -r '.overrides.axios // ""' "${pkg_file}" 2>&1); then
		echo -e "  ${RED}[!] Cannot parse ${pkg_file} (jq error: ${existing}) — skipping override injection.${RESET}" >&2
		return 1
	fi
	if [[ "$existing" == "$safe_version" ]]; then
		echo -e "  ${GREEN}[i] overrides.axios already set to ${safe_version} in ${pkg_file}${RESET}"
		return
	fi

	local tmp_file="${pkg_file}.tmp"
	# Write to a temp file first so the original is not truncated if jq fails mid-run
	trap 'rm -f "${tmp_file}"' RETURN
	if ! jq --arg v "${safe_version}" '.overrides.axios = $v' "${pkg_file}" > "${tmp_file}"; then
		echo -e "  ${RED}[!] jq failed writing to ${tmp_file} — ${pkg_file} NOT modified.${RESET}" >&2
		return 1
	fi
	if ! mv "${tmp_file}" "${pkg_file}"; then
		echo -e "  ${RED}[!] Failed to rename temp file — original intact. Temp file left at ${tmp_file}.${RESET}" >&2
		return 1
	fi
	echo -e "  ${GREEN}[+] Injected overrides.axios = \"${safe_version}\" into ${pkg_file}${RESET}"
}

print_credential_rotation_warning() {
	echo -e "${RED}${BOLD}"
	echo "╔══════════════════════════════════════════════════════════════════╗"
	echo "║  ⚠️  CRITICAL: ROTATE ALL CREDENTIALS IMMEDIATELY               ║"
	echo "╠══════════════════════════════════════════════════════════════════╣"
	echo "║  A compromised axios version was found. The malware drops a RAT  ║"
	echo "║  that exfiltrates secrets. Assume full system compromise.        ║"
	echo "║                                                                  ║"
	echo "║  Rotate NOW:                                                     ║"
	echo "║   • SSH keys      : ~/.ssh/ — revoke & regenerate all keypairs   ║"
	echo "║   • Git tokens    : GitHub / GitLab / Bitbucket PATs             ║"
	echo "║   • npm tokens    : .npmrc tokens / Artifactory / Nexus          ║"
	echo "║   • Cloud creds   : AWS, Azure, GCP — rotate IAM keys/svc accts  ║"
	echo "║   • DB passwords  : Postgres, MySQL, MongoDB, Redis, etc.        ║"
	echo "║   • CI/CD secrets : GitHub Actions, GitLab CI, Azure DevOps vars ║"
	echo "║   • .env files    : all API keys, secrets, connection strings     ║"
	echo "║   • Docker Hub    : container registry credentials               ║"
	echo "║   • Shell history : tokens cached in history or config files     ║"
	echo "║                                                                  ║"
	echo "║  C2 seen at: sfrclak.com:8000 / 142.11.206.73                   ║"
	echo "║  Block this IP/domain in your firewall immediately.              ║"
	echo "╚══════════════════════════════════════════════════════════════════╝"
	echo -e "${RESET}"
}

# ─── Preflight: dependency check ──────────────────────────────────────────────

echo -e "${CYAN}[*] Dependency check:${RESET}"

if command -v pnpm &>/dev/null; then
	echo -e "    ${GREEN}pnpm    ✓ found${RESET}"
fi
if command -v yarn &>/dev/null; then
	echo -e "    ${GREEN}yarn    ✓ found${RESET}"
fi
if command -v npm &>/dev/null; then
	echo -e "    ${GREEN}npm     ✓ found${RESET}"
else
	echo -e "    ${YELLOW}npm     ✗ missing — falling back to node_modules/axios/package.json inspection${RESET}"
	echo -e "             (transitive/hoisted installs may be missed)"
fi
if ! command -v pnpm &>/dev/null && ! command -v yarn &>/dev/null && ! command -v npm &>/dev/null; then
	echo -e "    ${RED}No package manager found (npm/pnpm/yarn) — version detection will use file fallback only${RESET}"
fi

if command -v jq &>/dev/null; then
	echo -e "    ${GREEN}jq      ✓ found — overrides injection will preserve JSON types and array structure (formatting may change)${RESET}"
else
	echo -e "    ${YELLOW}jq      ✗ missing — overrides injection disabled; mitigation steps will be printed instead${RESET}"
	echo -e "             (install jq: https://jqlang.org/download/)"
fi

if command -v ss &>/dev/null || command -v netstat &>/dev/null; then
	echo -e "    ${GREEN}ss/netstat ✓ found — C2 connection check active${RESET}"
else
	echo -e "    ${YELLOW}ss/netstat ✗ missing — skipping live C2 connection check${RESET}"
fi

echo ""

# ─── 1. Check active C2 connections ───────────────────────────────────────────

echo -e "${CYAN}[*] Checking for active C2 connections to ${C2_IP} (IP only — domain ${C2_DOMAIN} is not resolved in socket output)...${RESET}"
if command -v ss &>/dev/null; then
	if ss -tn 2>/dev/null | grep -qF "${C2_IP}"; then
		echo -e "${RED}[!!!] LIVE C2 CONNECTION DETECTED — system is actively compromised!${RESET}"
		FOUND_RAT=1
	fi
elif command -v netstat &>/dev/null; then
	if netstat -an 2>/dev/null | grep -qF "${C2_IP}"; then
		echo -e "${RED}[!!!] LIVE C2 CONNECTION DETECTED — system is actively compromised!${RESET}"
		FOUND_RAT=1
	fi
fi

# ─── 2. Check Linux-specific RAT artifact ─────────────────────────────────────

if [[ "$(uname -s)" == "Linux" ]]; then
	echo -e "${CYAN}[*] Checking for Linux RAT artifact /tmp/ld.py...${RESET}"
	if [[ -f /tmp/ld.py ]]; then
		echo -e "${RED}[!!!] COMPROMISED — /tmp/ld.py found. This is a known RAT dropper artifact.${RESET}"
		FOUND_RAT=1
	else
		echo -e "${GREEN}    [OK] /tmp/ld.py not present.${RESET}"
	fi
fi
echo ""

# ─── 3. Scan for Node.js projects ─────────────────────────────────────────────

echo -e "${CYAN}[*] Scanning ${SCAN_ROOT} for Node.js projects...${RESET}"

PACKAGE_FILES=()
_find_errors=$(mktemp)
while IFS= read -r _pkg; do
	PACKAGE_FILES+=("$_pkg")
done < <(
	find "${SCAN_ROOT}" \
		-name "package.json" \
		-not -path "*/node_modules/*" \
		-not -path "*/.git/*" \
		-not -path "*/.cache/*" \
		2>"${_find_errors}"
)
_skipped=$(grep -c . "${_find_errors}" 2>/dev/null || echo 0)
rm -f "${_find_errors}"
if [[ "${_skipped}" -gt 0 ]]; then
	echo -e "${YELLOW}[!] ${_skipped} director(ies) could not be scanned (permission denied). Run as root for full coverage.${RESET}"
fi

echo -e "${CYAN}[*] Found ${#PACKAGE_FILES[@]} project package.json file(s). Inspecting...${RESET}"
echo ""

for pkg_file in "${PACKAGE_FILES[@]}"; do
	project_dir="$(dirname "${pkg_file}")"

	# ── Detect installed axios version via package manager list ──────────────
	if [[ ! -d "${project_dir}" ]]; then
		echo -e "  ${YELLOW}[!] Skipping ${project_dir} — directory not accessible.${RESET}" >&2
		continue
	fi
	pkg_manager="$(detect_package_manager "${project_dir}")"
	installed_version=""
	if command -v "${pkg_manager}" &>/dev/null && [[ -d "${project_dir}/node_modules" ]]; then
		case "${pkg_manager}" in
			pnpm)
				installed_version=$(
					cd "${project_dir}" &&
					pnpm list axios 2>/dev/null | grep -oE 'axios@[0-9]+\.[0-9]+\.[0-9]+' | sed 's/axios@//' | head -1 || true
				) ;;
			yarn)
				installed_version=$(
					cd "${project_dir}" &&
					yarn list --pattern axios 2>/dev/null | grep -oE 'axios@[0-9]+\.[0-9]+\.[0-9]+' | sed 's/axios@//' | head -1 || true
				) ;;
			*)
				installed_version=$(
					cd "${project_dir}" &&
					npm list axios 2>/dev/null | grep -oE 'axios@[0-9]+\.[0-9]+\.[0-9]+' | sed 's/axios@//' | head -1 || true
				) ;;
		esac
	fi

	# Fallback: read node_modules/axios/package.json directly
	if [[ -z "${installed_version}" && -f "${project_dir}/node_modules/axios/package.json" ]]; then
		if command -v jq &>/dev/null; then
			installed_version=$(jq -r '.version // ""' "${project_dir}/node_modules/axios/package.json" 2>/dev/null || true)
		else
			installed_version=$(grep -m1 '"version"' "${project_dir}/node_modules/axios/package.json" \
				| grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)
		fi
	fi

	# ── Declared version in package.json (for projects without node_modules) ─
	declared_version=""
	if [[ -z "${installed_version}" ]]; then
		if command -v jq &>/dev/null; then
			declared_version=$(jq -r '
				(.dependencies["axios"] // .devDependencies["axios"] // "") |
				ltrimstr("^") | ltrimstr("~") | ltrimstr(">=") | ltrimstr("<=") | ltrimstr(">") | ltrimstr("<") | ltrimstr("=")
			' "${pkg_file}" 2>/dev/null || true)
		else
			declared_version=$(grep -E '"axios"[[:space:]]*:' "${pkg_file}" 2>/dev/null \
				| grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
		fi
	fi

	# ── Check for malicious plain-crypto-js in node_modules ─────────────────
	rat_present=0
	if [[ -d "${project_dir}/node_modules/plain-crypto-js" ]]; then
		echo -e "${RED}[CRITICAL] ${project_dir}${RESET}"
		echo -e "  plain-crypto-js : found in node_modules — RAT dropper present!"
		FOUND_RAT=1
		rat_present=1
	fi

	project_flagged=0
	affected_branch=""

	if [[ -n "${installed_version}" ]] && is_affected_axios_version "${installed_version}"; then
		echo -e "${RED}[INFECTED]  ${project_dir}${RESET}"
		echo -e "  axios installed : ${RED}${installed_version}${RESET} (AFFECTED)"
		FOUND_AFFECTED=1
		project_flagged=1
		[[ "${installed_version}" == 0.* ]] && affected_branch="0.x" || affected_branch="1.x"
	elif [[ -n "${declared_version}" ]] && is_affected_axios_version "${declared_version}"; then
		echo -e "${YELLOW}[WARNING]   ${project_dir}${RESET}"
		echo -e "  axios declared  : ${YELLOW}${declared_version}${RESET} (run ${pkg_manager} install to confirm)"
		FOUND_AFFECTED=1
		project_flagged=1
		[[ "${declared_version}" == 0.* ]] && affected_branch="0.x" || affected_branch="1.x"
	fi

	# Axios-specific mitigation (only when axios affected version detected)
	if [[ "${project_flagged}" -eq 1 ]]; then
		local_safe=$( [[ "${affected_branch}" == "0.x" ]] && echo "0.30.3" || echo "1.14.0" )
		echo -e "  Project         : ${pkg_file}"
		echo ""
		echo -e "  ${YELLOW}Mitigation:${RESET}"
		echo -e "  1. cd \"${project_dir}\""
		case "${pkg_manager}" in
			pnpm) echo -e "  2. pnpm add axios@${local_safe}" ;;
			yarn) echo -e "  2. yarn add axios@${local_safe}" ;;
			*)    echo -e "  2. npm install axios@${local_safe}" ;;
		esac
		echo -e "  3. rm -rf node_modules/plain-crypto-js"
		case "${pkg_manager}" in
			pnpm) echo -e "  4. pnpm install --ignore-scripts" ;;
			yarn) echo -e "  4. yarn install --ignore-scripts" ;;
			*)    echo -e "  4. npm install --ignore-scripts    # reinstall without running postinstall hooks" ;;
		esac
		echo ""
		inject_overrides "${pkg_file}" "${affected_branch}"
		echo ""
	fi

	# RAT-only mitigation (plain-crypto-js present but no affected axios version detected)
	if [[ "${rat_present}" -eq 1 && "${project_flagged}" -eq 0 ]]; then
		echo -e "  Project         : ${pkg_file}"
		echo ""
		echo -e "  ${YELLOW}Mitigation (RAT dropper found, no affected axios version detected):${RESET}"
		echo -e "  1. cd \"${project_dir}\""
		echo -e "  2. rm -rf node_modules/plain-crypto-js"
		case "${pkg_manager}" in
			pnpm) echo -e "  3. pnpm install --ignore-scripts" ;;
			yarn) echo -e "  3. yarn install --ignore-scripts" ;;
			*)    echo -e "  3. npm install --ignore-scripts    # reinstall without running postinstall hooks" ;;
		esac
		echo ""
	fi
done

# ─── Summary ──────────────────────────────────────────────────────────────────

echo "────────────────────────────────────────────────────────"
if [[ "${FOUND_AFFECTED}" -eq 0 && "${FOUND_RAT}" -eq 0 ]]; then
	echo -e "${GREEN}[✓] No affected axios versions or malicious packages found.${RESET}"
	echo -e "${GREEN}    Consider pinning axios via package.json overrides as a precaution.${RESET}"
else
	print_credential_rotation_warning
fi
echo "────────────────────────────────────────────────────────"
