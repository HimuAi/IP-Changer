#!/bin/bash

################################################################################
# IP-Changer Script (IPC.sh)
# A robust script for managing and changing IP configurations
# 
# Features:
# - Comprehensive error handling and validation
# - Detailed logging for debugging and audit trails
# - Automatic cleanup of temporary files
# - Security improvements and input validation
# - Graceful signal handling
#
# Author: HimuAi
# Version: 2.0
# Last Updated: 2026-01-05
################################################################################

set -euo pipefail

# Script configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly LOG_DIR="${SCRIPT_DIR}/logs"
readonly LOG_FILE="${LOG_DIR}/ipc_$(date +%Y%m%d_%H%M%S).log"
readonly TEMP_DIR="/tmp/ipc_$$"
readonly PID_FILE="/var/run/ipc_${$}.pid"

# Global variables
VERBOSE=0
DRY_RUN=0
ERROR_COUNT=0
SUCCESS_COUNT=0

################################################################################
# Logging Functions
################################################################################

# Initialize logging
initialize_logging() {
    if [[ ! -d "${LOG_DIR}" ]]; then
        mkdir -p "${LOG_DIR}" || {
            echo "ERROR: Failed to create log directory: ${LOG_DIR}" >&2
            exit 1
        }
    fi
    
    # Create log file with appropriate permissions
    touch "${LOG_FILE}"
    chmod 600 "${LOG_FILE}"
    
    log "INFO" "Script started: ${SCRIPT_NAME}"
    log "INFO" "Log file: ${LOG_FILE}"
}

# Log function with timestamp and severity levels
log() {
    local level="$1"
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S UTC')
    
    local log_entry="${timestamp} [${level}] ${message}"
    
    # Write to log file
    echo "${log_entry}" >> "${LOG_FILE}"
    
    # Output to console if verbose or error level
    if [[ ${VERBOSE} -eq 1 ]] || [[ "${level}" == "ERROR" ]] || [[ "${level}" == "CRITICAL" ]]; then
        echo "${log_entry}" >&2
    fi
}

################################################################################
# Error Handling & Cleanup Functions
################################################################################

# Cleanup function - called on exit or signal
cleanup() {
    local exit_code=$?
    
    log "INFO" "Cleaning up temporary files and resources..."
    
    # Remove temporary directory
    if [[ -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}" || log "WARN" "Failed to remove temp directory: ${TEMP_DIR}"
    fi
    
    # Remove PID file
    if [[ -f "${PID_FILE}" ]]; then
        rm -f "${PID_FILE}" || log "WARN" "Failed to remove PID file: ${PID_FILE}"
    fi
    
    # Log final statistics
    log "INFO" "Script completed with exit code: ${exit_code}"
    log "INFO" "Successful operations: ${SUCCESS_COUNT}"
    log "INFO" "Failed operations: ${ERROR_COUNT}"
    
    return "${exit_code}"
}

# Error handler function
error_handler() {
    local line_number=$1
    local error_code=$2
    
    ((ERROR_COUNT++))
    log "ERROR" "Error occurred at line ${line_number} with exit code ${error_code}"
    log "ERROR" "Stack trace: $(caller)"
}

# Register cleanup and error handlers
trap cleanup EXIT
trap 'error_handler ${LINENO} $?' ERR
trap 'log "WARN" "Script interrupted by user"; exit 130' INT TERM

################################################################################
# Validation Functions
################################################################################

# Validate if running as root
check_root_privilege() {
    if [[ $EUID -ne 0 ]]; then
        log "CRITICAL" "This script must be run as root"
        exit 1
    fi
    log "INFO" "Root privileges verified"
}

# Validate IP address format
validate_ip_address() {
    local ip="$1"
    
    if [[ ! ${ip} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log "ERROR" "Invalid IP address format: ${ip}"
        return 1
    fi
    
    # Validate each octet
    local IFS='.'
    local -a octets=($ip)
    for octet in "${octets[@]}"; do
        if [[ ${octet} -gt 255 ]]; then
            log "ERROR" "Invalid IP octet value: ${octet}"
            return 1
        fi
    done
    
    return 0
}

# Validate network interface exists
validate_interface() {
    local interface="$1"
    
    if ! ip link show "${interface}" &>/dev/null; then
        log "ERROR" "Network interface not found: ${interface}"
        return 1
    fi
    log "INFO" "Network interface validated: ${interface}"
}

# Validate subnet mask
validate_netmask() {
    local netmask="$1"
    
    if ! validate_ip_address "${netmask}"; then
        return 1
    fi
    
    # Additional subnet mask validation logic can be added here
    return 0
}

################################################################################
# Network Configuration Functions
################################################################################

# Get current IP configuration
get_current_ip_config() {
    local interface="$1"
    
    log "INFO" "Retrieving current IP configuration for interface: ${interface}"
    
    local config_file="${TEMP_DIR}/current_config_${interface}.txt"
    mkdir -p "${TEMP_DIR}"
    
    if ip addr show "${interface}" > "${config_file}" 2>&1; then
        log "INFO" "Current configuration saved to: ${config_file}"
        cat "${config_file}"
        return 0
    else
        log "ERROR" "Failed to retrieve IP configuration for interface: ${interface}"
        return 1
    fi
}

# Change IP address
change_ip_address() {
    local interface="$1"
    local ip_address="$2"
    local netmask="$3"
    
    log "INFO" "Attempting to change IP on interface ${interface} to ${ip_address}/${netmask}"
    
    # Validation
    validate_interface "${interface}" || return 1
    validate_ip_address "${ip_address}" || return 1
    validate_netmask "${netmask}" || return 1
    
    # Save current configuration for rollback
    local backup_file="${TEMP_DIR}/backup_${interface}_$(date +%s).conf"
    get_current_ip_config "${interface}" > "${backup_file}" 2>&1 || {
        log "WARN" "Failed to backup current configuration"
    }
    
    # Perform IP change (dry-run or actual)
    if [[ ${DRY_RUN} -eq 1 ]]; then
        log "INFO" "[DRY RUN] Would execute: ip addr add ${ip_address}/${netmask} dev ${interface}"
        return 0
    fi
    
    if ip addr add "${ip_address}/${netmask}" dev "${interface}" 2>&1 | tee -a "${LOG_FILE}"; then
        ((SUCCESS_COUNT++))
        log "INFO" "Successfully changed IP address on ${interface}"
        return 0
    else
        ((ERROR_COUNT++))
        log "ERROR" "Failed to change IP address on ${interface}"
        log "INFO" "Backup configuration available at: ${backup_file}"
        return 1
    fi
}

# Flush IP address
flush_ip_address() {
    local interface="$1"
    
    log "INFO" "Flushing IP addresses from interface: ${interface}"
    
    validate_interface "${interface}" || return 1
    
    if [[ ${DRY_RUN} -eq 1 ]]; then
        log "INFO" "[DRY RUN] Would execute: ip addr flush dev ${interface}"
        return 0
    fi
    
    if ip addr flush dev "${interface}" 2>&1 | tee -a "${LOG_FILE}"; then
        ((SUCCESS_COUNT++))
        log "INFO" "Successfully flushed IP addresses from ${interface}"
        return 0
    else
        ((ERROR_COUNT++))
        log "ERROR" "Failed to flush IP addresses from ${interface}"
        return 1
    fi
}

################################################################################
# Utility Functions
################################################################################

# Display usage information
usage() {
    cat << EOF
Usage: ${SCRIPT_NAME} [OPTIONS] COMMAND [ARGUMENTS]

COMMANDS:
    show INTERFACE              Display current IP configuration
    change INTERFACE IP NETMASK Change IP address on interface
    flush INTERFACE             Remove all IP addresses from interface

OPTIONS:
    -h, --help                  Show this help message
    -v, --verbose               Enable verbose output
    -d, --dry-run               Show what would be executed without making changes
    
EXAMPLES:
    ${SCRIPT_NAME} show eth0
    ${SCRIPT_NAME} -v change eth0 192.168.1.100 255.255.255.0
    ${SCRIPT_NAME} -d flush eth0

EOF
}

# Display version
show_version() {
    echo "${SCRIPT_NAME} version 2.0"
    echo "IP Configuration Management Script"
}

################################################################################
# Main Functions
################################################################################

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=1
                log "INFO" "Dry-run mode enabled"
                shift
                ;;
            --version)
                show_version
                exit 0
                ;;
            -*)
                log "ERROR" "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                break
                ;;
        esac
    done
    
    # Return remaining arguments
    echo "$@"
}

# Main execution function
main() {
    # Initialize logging
    initialize_logging
    
    # Check root privileges
    check_root_privilege
    
    # Parse arguments
    local remaining_args
    remaining_args=$(parse_arguments "$@")
    
    local -a args=($remaining_args)
    
    if [[ ${#args[@]} -eq 0 ]]; then
        log "ERROR" "No command specified"
        usage
        exit 1
    fi
    
    local command="${args[0]}"
    
    case "${command}" in
        show)
            if [[ ${#args[@]} -lt 2 ]]; then
                log "ERROR" "Interface argument required for 'show' command"
                exit 1
            fi
            get_current_ip_config "${args[1]}"
            ;;
        change)
            if [[ ${#args[@]} -lt 4 ]]; then
                log "ERROR" "Interface, IP address, and netmask arguments required for 'change' command"
                exit 1
            fi
            change_ip_address "${args[1]}" "${args[2]}" "${args[3]}"
            ;;
        flush)
            if [[ ${#args[@]} -lt 2 ]]; then
                log "ERROR" "Interface argument required for 'flush' command"
                exit 1
            fi
            flush_ip_address "${args[1]}"
            ;;
        *)
            log "ERROR" "Unknown command: ${command}"
            usage
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"
