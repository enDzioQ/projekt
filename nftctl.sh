#!/usr/bin/env bash
set -euo pipefail

APP_NAME="nftctl"
CONFIG_FILE="${NFTCTL_CONFIG_FILE:-/etc/nftctl.conf}"
BACKUP_DIR="${NFTCTL_BACKUP_DIR:-/var/lib/nftctl/backups}"
TABLE_FAMILY="inet"
TABLE_NAME="nftctl"
CHAIN_NAME="input"

BLACKLISTED_IPS=()
WHITELISTED_TCP_PORTS=()
WHITELISTED_UDP_PORTS=()
FIREWALL_MODE="monitor"

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
CYAN="\033[36m"
BOLD="\033[1m"
RESET="\033[0m"

hr() {
    printf '%*s\n' "${COLUMNS:-72}" '' | tr ' ' '-'
}

banner() {
    clear || true
    printf '%b\n' "${BOLD}${CYAN}============================================================${RESET}"
    printf '%b\n' "${BOLD}${CYAN}  nftctl - console firewall manager for nftables${RESET}"
    printf '%b\n' "${BOLD}${CYAN}============================================================${RESET}"
    printf '%b\n' "${YELLOW}Config:${RESET} %s\n" "$CONFIG_FILE"
    printf '%b\n' "${YELLOW}Backup:${RESET} %s\n" "$BACKUP_DIR"
    printf '%b\n' "${YELLOW}Mode:${RESET} %s\n" "$FIREWALL_MODE"
    hr
}

info() { printf '%b[INFO]%b %s\n' "$BLUE" "$RESET" "$*"; }
success() { printf '%b[OK]%b %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%b[WARN]%b %s\n' "$YELLOW" "$RESET" "$*"; }
fatal() { printf '%b[ERR]%b %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        fatal "Uruchom ten skrypt jako root, np. przez: sudo $0"
    fi
}

require_nft() {
    command -v nft >/dev/null 2>&1 || fatal "Brak polecenia nft. Zainstaluj nftables."
}

ensure_dirs() {
    mkdir -p "$(dirname "$CONFIG_FILE")"
    mkdir -p "$BACKUP_DIR"
}

join_by() {
    local delimiter="$1"
    shift
    local first=1
    local value
    for value in "$@"; do
        if (( first )); then
            printf '%s' "$value"
            first=0
        else
            printf '%s%s' "$delimiter" "$value"
        fi
    done
}

array_contains() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

array_add_unique() {
    local -n target_array="$1"
    local value="$2"
    if ! array_contains "$value" "${target_array[@]:-}"; then
        target_array+=("$value")
    fi
}

array_remove_value() {
    local -n target_array="$1"
    local value="$2"
    local filtered=()
    local item
    for item in "${target_array[@]:-}"; do
        [[ "$item" == "$value" ]] || filtered+=("$item")
    done
    target_array=("${filtered[@]:-}")
}

is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_ipv6() {
    [[ "$1" == *:* ]]
}

validate_ip() {
    local ip="$1"
    if is_ipv4 "$ip"; then
        local octet
        IFS='.' read -r -a octets <<<"$ip"
        for octet in "${octets[@]}"; do
            [[ "$octet" =~ ^[0-9]+$ ]] || return 1
            (( octet >= 0 && octet <= 255 )) || return 1
        done
        return 0
    fi

    if is_ipv6 "$ip"; then
        command -v python3 >/dev/null 2>&1 && python3 - <<'PY' "$ip" >/dev/null 2>&1
import ipaddress, sys
ipaddress.IPv6Address(sys.argv[1])
PY
        return $?
    fi

    return 1
}

validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    (( port >= 1 && port <= 65535 ))
}

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$CONFIG_FILE"
    else
        save_config
    fi

    FIREWALL_MODE="${FIREWALL_MODE:-monitor}"
    BLACKLISTED_IPS=("${BLACKLISTED_IPS[@]:-}")
    WHITELISTED_TCP_PORTS=("${WHITELISTED_TCP_PORTS[@]:-}")
    WHITELISTED_UDP_PORTS=("${WHITELISTED_UDP_PORTS[@]:-}")
}

save_config() {
    local temp_file
    temp_file="$(mktemp)"
    {
        printf '# nftctl configuration\n'
        printf 'FIREWALL_MODE=%q\n' "$FIREWALL_MODE"
        printf 'BLACKLISTED_IPS=(%s)\n' "$(printf '%q ' "${BLACKLISTED_IPS[@]:-}")"
        printf 'WHITELISTED_TCP_PORTS=(%s)\n' "$(printf '%q ' "${WHITELISTED_TCP_PORTS[@]:-}")"
        printf 'WHITELISTED_UDP_PORTS=(%s)\n' "$(printf '%q ' "${WHITELISTED_UDP_PORTS[@]:-}")"
    } >"$temp_file"
    mv "$temp_file" "$CONFIG_FILE"
}

backup_live_ruleset() {
    local backup_file
    backup_file="$BACKUP_DIR/nftctl-$(date +%Y%m%d-%H%M%S).nft"
    nft list table "$TABLE_FAMILY" "$TABLE_NAME" >"$backup_file" 2>/dev/null || true
}

generate_ruleset() {
    local policy="accept"
    [[ "$FIREWALL_MODE" == "strict" ]] && policy="drop"

    local ipv4_elements
    local ipv6_elements
    local tcp_elements
    local udp_elements

    ipv4_elements="$(join_by ', ' "${BLACKLISTED_IPS_V4[@]:-}")"
    ipv6_elements="$(join_by ', ' "${BLACKLISTED_IPS_V6[@]:-}")"
    tcp_elements="$(join_by ', ' "${WHITELISTED_TCP_PORTS[@]:-}")"
    udp_elements="$(join_by ', ' "${WHITELISTED_UDP_PORTS[@]:-}")"

    cat <<EOF
flush table inet nftctl

table inet nftctl {
    set blacklist_v4 {
        type ipv4_addr
        elements = { ${ipv4_elements} }
    }

    set blacklist_v6 {
        type ipv6_addr
        elements = { ${ipv6_elements} }
    }

    set allow_tcp_ports {
        type inet_service
        elements = { ${tcp_elements} }
    }

    set allow_udp_ports {
        type inet_service
        elements = { ${udp_elements} }
    }

    chain input {
        type filter hook input priority 0; policy ${policy};
        ct state established,related accept
        ct state invalid drop
        iif "lo" accept
        ip saddr @blacklist_v4 drop
        ip6 saddr @blacklist_v6 drop
        tcp dport @allow_tcp_ports accept
        udp dport @allow_udp_ports accept
        icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded, parameter-problem } accept
        icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
    }
}
EOF
}

apply_rules() {
    require_root
    require_nft
    backup_live_ruleset

    local tmp_rules
    tmp_rules="$(mktemp)"
    generate_ruleset >"$tmp_rules"
    nft -f "$tmp_rules"
    rm -f "$tmp_rules"
    success "Reguły zostały zastosowane."
}

split_ips() {
    BLACKLISTED_IPS_V4=()
    BLACKLISTED_IPS_V6=()

    local ip
    for ip in "${BLACKLISTED_IPS[@]:-}"; do
        if is_ipv4 "$ip"; then
            BLACKLISTED_IPS_V4+=("$ip")
        else
            BLACKLISTED_IPS_V6+=("$ip")
        fi
    done
}

show_status() {
    banner
    printf '%b\n' "${BOLD}Current entries${RESET}"
    printf 'Blacklisted IPs : %s\n' "${#BLACKLISTED_IPS[@]}"
    printf 'TCP whitelist   : %s\n' "${#WHITELISTED_TCP_PORTS[@]}"
    printf 'UDP whitelist   : %s\n' "${#WHITELISTED_UDP_PORTS[@]}"
    printf 'Firewall mode   : %s\n' "$FIREWALL_MODE"
    hr

    if [[ ${#BLACKLISTED_IPS[@]} -eq 0 ]]; then
        printf 'Blacklisted IPs : none\n'
    else
        printf '%bBlacklisted IPs%b\n' "$BOLD" "$RESET"
        printf '  %s\n' "$(join_by $'\n  ' "${BLACKLISTED_IPS[@]}")"
    fi

    if [[ ${#WHITELISTED_TCP_PORTS[@]} -eq 0 ]]; then
        printf 'TCP whitelist   : none\n'
    else
        printf '%bTCP whitelist%b\n' "$BOLD" "$RESET"
        printf '  %s\n' "$(join_by $'\n  ' "${WHITELISTED_TCP_PORTS[@]}")"
    fi

    if [[ ${#WHITELISTED_UDP_PORTS[@]} -eq 0 ]]; then
        printf 'UDP whitelist   : none\n'
    else
        printf '%bUDP whitelist%b\n' "$BOLD" "$RESET"
        printf '  %s\n' "$(join_by $'\n  ' "${WHITELISTED_UDP_PORTS[@]}")"
    fi

    hr
    if command -v nft >/dev/null 2>&1; then
        nft list table inet nftctl 2>/dev/null || warn "Tabela inet nftctl nie istnieje jeszcze w nftables."
    fi
}

prompt() {
    local message="$1"
    local reply
    read -r -p "$message" reply
    printf '%s' "$reply"
}

confirm() {
    local message="$1"
    local answer
    read -r -p "$message [y/N]: " answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

add_ip_flow() {
    local ip
    ip="$(prompt "Podaj adres IP do blacklisty: ")"
    validate_ip "$ip" || fatal "Niepoprawny adres IP."
    array_add_unique BLACKLISTED_IPS "$ip"
    save_config
    split_ips
    apply_rules
}

remove_ip_flow() {
    local ip
    ip="$(prompt "Podaj adres IP do usunięcia: ")"
    validate_ip "$ip" || fatal "Niepoprawny adres IP."
    array_remove_value BLACKLISTED_IPS "$ip"
    save_config
    split_ips
    apply_rules
}

add_port_flow() {
    local proto
    proto="$(prompt "Protokół (tcp/udp/both): ")"
    local port
    port="$(prompt "Podaj port do whitelisty: ")"
    validate_port "$port" || fatal "Niepoprawny numer portu."

    case "$proto" in
        tcp)
            array_add_unique WHITELISTED_TCP_PORTS "$port"
            ;;
        udp)
            array_add_unique WHITELISTED_UDP_PORTS "$port"
            ;;
        both)
            array_add_unique WHITELISTED_TCP_PORTS "$port"
            array_add_unique WHITELISTED_UDP_PORTS "$port"
            ;;
        *)
            fatal "Dozwolone wartości: tcp, udp, both."
            ;;
    esac

    save_config
    split_ips
    apply_rules
}

remove_port_flow() {
    local proto
    proto="$(prompt "Protokół (tcp/udp/both): ")"
    local port
    port="$(prompt "Podaj port do usunięcia: ")"
    validate_port "$port" || fatal "Niepoprawny numer portu."

    case "$proto" in
        tcp)
            array_remove_value WHITELISTED_TCP_PORTS "$port"
            ;;
        udp)
            array_remove_value WHITELISTED_UDP_PORTS "$port"
            ;;
        both)
            array_remove_value WHITELISTED_TCP_PORTS "$port"
            array_remove_value WHITELISTED_UDP_PORTS "$port"
            ;;
        *)
            fatal "Dozwolone wartości: tcp, udp, both."
            ;;
    esac

    save_config
    split_ips
    apply_rules
}

toggle_mode_flow() {
    local next_mode
    if [[ "$FIREWALL_MODE" == "strict" ]]; then
        next_mode="monitor"
    else
        next_mode="strict"
    fi

    printf 'Aktualny tryb: %s\n' "$FIREWALL_MODE"
    if confirm "Przełączyć na ${next_mode}?"; then
        FIREWALL_MODE="$next_mode"
        save_config
        split_ips
        apply_rules
    fi
}

list_data_flow() {
    show_status
    printf '\nNaciśnij Enter, aby wrócić do menu...'
    read -r _
}

interactive_menu() {
    while true; do
        banner
        printf '%b\n' "${BOLD}Menu${RESET}"
        printf '1) Pokaż status\n'
        printf '2) Dodaj IP do blacklisty\n'
        printf '3) Usuń IP z blacklisty\n'
        printf '4) Dodaj port do whitelisty\n'
        printf '5) Usuń port z whitelisty\n'
        printf '6) Przełącz tryb strict/monitor\n'
        printf '7) Zastosuj reguły teraz\n'
        printf '8) Wyjście\n'
        hr
        local choice
        choice="$(prompt "Wybierz opcję: ")"
        case "$choice" in
            1) list_data_flow ;;
            2) add_ip_flow ;;
            3) remove_ip_flow ;;
            4) add_port_flow ;;
            5) remove_port_flow ;;
            6) toggle_mode_flow ;;
            7)
                split_ips
                apply_rules
                read -r -p "Naciśnij Enter, aby wrócić do menu..." _
                ;;
            8|q|Q|quit|exit)
                exit 0
                ;;
            *)
                warn "Nieznana opcja."
                sleep 1
                ;;
        esac
    done
}

print_help() {
    cat <<EOF
$nftctl - console firewall manager for nftables

Usage:
  $0 menu
  $0 status
  $0 add-ip <ip>
  $0 del-ip <ip>
  $0 add-port <tcp|udp|both> <port>
  $0 del-port <tcp|udp|both> <port>
  $0 mode <monitor|strict>
  $0 apply

Environment variables:
  NFTCTL_CONFIG_FILE   Path to config file (default: /etc/nftctl.conf)
  NFTCTL_BACKUP_DIR    Directory for rule backups (default: /var/lib/nftctl/backups)
EOF
}

cmd_add_ip() {
    local ip="$1"
    validate_ip "$ip" || fatal "Niepoprawny adres IP."
    array_add_unique BLACKLISTED_IPS "$ip"
    save_config
    split_ips
    apply_rules
}

cmd_del_ip() {
    local ip="$1"
    validate_ip "$ip" || fatal "Niepoprawny adres IP."
    array_remove_value BLACKLISTED_IPS "$ip"
    save_config
    split_ips
    apply_rules
}

cmd_add_port() {
    local proto="$1"
    local port="$2"
    validate_port "$port" || fatal "Niepoprawny numer portu."
    case "$proto" in
        tcp)
            array_add_unique WHITELISTED_TCP_PORTS "$port"
            ;;
        udp)
            array_add_unique WHITELISTED_UDP_PORTS "$port"
            ;;
        both)
            array_add_unique WHITELISTED_TCP_PORTS "$port"
            array_add_unique WHITELISTED_UDP_PORTS "$port"
            ;;
        *)
            fatal "Dozwolone wartości: tcp, udp, both."
            ;;
    esac
    save_config
    split_ips
    apply_rules
}

cmd_del_port() {
    local proto="$1"
    local port="$2"
    validate_port "$port" || fatal "Niepoprawny numer portu."
    case "$proto" in
        tcp)
            array_remove_value WHITELISTED_TCP_PORTS "$port"
            ;;
        udp)
            array_remove_value WHITELISTED_UDP_PORTS "$port"
            ;;
        both)
            array_remove_value WHITELISTED_TCP_PORTS "$port"
            array_remove_value WHITELISTED_UDP_PORTS "$port"
            ;;
        *)
            fatal "Dozwolone wartości: tcp, udp, both."
            ;;
    esac
    save_config
    split_ips
    apply_rules
}

cmd_mode() {
    local mode="$1"
    case "$mode" in
        monitor|strict)
            FIREWALL_MODE="$mode"
            save_config
            split_ips
            apply_rules
            ;;
        *)
            fatal "Dozwolone tryby: monitor, strict."
            ;;
    esac
}

main() {
    require_nft
    ensure_dirs
    load_config
    split_ips

    local command="${1:-menu}"
    case "$command" in
        menu)
            require_root
            interactive_menu
            ;;
        status)
            show_status
            ;;
        add-ip)
            require_root
            [[ $# -eq 2 ]] || fatal "Użycie: $0 add-ip <ip>"
            cmd_add_ip "$2"
            ;;
        del-ip)
            require_root
            [[ $# -eq 2 ]] || fatal "Użycie: $0 del-ip <ip>"
            cmd_del_ip "$2"
            ;;
        add-port)
            require_root
            [[ $# -eq 3 ]] || fatal "Użycie: $0 add-port <tcp|udp|both> <port>"
            cmd_add_port "$2" "$3"
            ;;
        del-port)
            require_root
            [[ $# -eq 3 ]] || fatal "Użycie: $0 del-port <tcp|udp|both> <port>"
            cmd_del_port "$2" "$3"
            ;;
        mode)
            require_root
            [[ $# -eq 2 ]] || fatal "Użycie: $0 mode <monitor|strict>"
            cmd_mode "$2"
            ;;
        apply)
            require_root
            apply_rules
            ;;
        help|-h|--help)
            print_help
            ;;
        *)
            fatal "Nieznana komenda: $command. Użyj --help."
            ;;
    esac
}

main "$@"
