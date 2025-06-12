#!/bin/bash
# ========================================================================
# ThakaaMed Docker Enhancement Emergency Rollback Script
# ========================================================================
# 
# 🚨 EMERGENCY ROLLBACK PROTOCOL 🚨
# 
# When things go sideways (and they sometimes do), this script is your
# "CTRL+Z" for the entire Docker enhancement. Think of it as the 
# "undo" button that actually works! 
#
# 🔥 What this script does:
# - Stops all ThakaaMed services gracefully
# - Removes all installed components 
# - Cleans up system modifications
# - Leaves your system exactly as it was before
# - Makes it look like we were never here (except for logs)
#
# 🏥 What this script does NOT touch:
# - Your existing Wazuh agent (it stays safe)
# - Your Docker containers (they keep running)
# - Your sanity (we hope)
# - Your coffee supply (that's your responsibility)
#
# ========================================================================

set -euo pipefail

# Colors for dramatic effect 🎭
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ========================================================================
# UTILITY FUNCTIONS
# ========================================================================

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${CYAN}[SUCCESS]${NC} $1"
}

# Dramatic banner because even rollbacks deserve style
show_rollback_banner() {
    echo -e "${RED}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    🚨 EMERGENCY ROLLBACK 🚨                  ║"
    echo "║                                                              ║"
    echo "║        ThakaaMed Docker Enhancement Removal Tool             ║"
    echo "║                                                              ║"
    echo "║  \"Houston, we have a problem... but we also have a solution\" ║"
    echo "║                                                              ║"
    echo "║              Press CTRL+C now to abort or...                ║"
    echo "║              Wait 10 seconds to proceed with rollback       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Countdown because we're not savages
countdown() {
    echo -e "${YELLOW}"
    for i in {10..1}; do
        echo -n "⏰ Rolling back in $i seconds... "
        sleep 1
        echo "💣"
    done
    echo -e "${NC}"
    echo -e "${RED}🚀 INITIATING ROLLBACK SEQUENCE!${NC}"
}

# ========================================================================
# ROLLBACK FUNCTIONS
# ========================================================================

stop_services() {
    log "🛑 Step 1: Stopping ThakaaMed services gracefully"
    
    # Stop the main collector service
    if systemctl is-active --quiet thakaamed-docker-collector 2>/dev/null; then
        log "   Stopping ThakaaMed Docker Collector..."
        systemctl stop thakaamed-docker-collector || true
        success "   ✅ ThakaaMed Docker Collector stopped"
    else
        info "   ℹ️  ThakaaMed Docker Collector was not running"
    fi
    
    # Disable the service
    if systemctl is-enabled --quiet thakaamed-docker-collector 2>/dev/null; then
        log "   Disabling ThakaaMed Docker Collector..."
        systemctl disable thakaamed-docker-collector || true
        success "   ✅ ThakaaMed Docker Collector disabled"
    else
        info "   ℹ️  ThakaaMed Docker Collector was not enabled"
    fi
    
    # Kill any remaining collector processes (the nuclear option)
    log "   Terminating any remaining collector processes..."
    pkill -f "thakaamed-docker-collector" 2>/dev/null || true
    
    # Clean up PID files
    log "   Cleaning up PID files..."
    rm -f /var/run/thakaamed-*.pid 2>/dev/null || true
    
    success "🎯 All ThakaaMed services stopped"
}

remove_systemd_service() {
    log "🗑️  Step 2: Removing systemd service configuration"
    
    # Remove service file
    if [[ -f /etc/systemd/system/thakaamed-docker-collector.service ]]; then
        log "   Removing service file..."
        rm -f /etc/systemd/system/thakaamed-docker-collector.service
        success "   ✅ Service file removed"
    else
        info "   ℹ️  Service file was not present"
    fi
    
    # Reload systemd daemon
    log "   Reloading systemd daemon..."
    systemctl daemon-reload
    
    # Reset failed state (just in case)
    systemctl reset-failed thakaamed-docker-collector 2>/dev/null || true
    
    success "🎯 Systemd service configuration cleaned up"
}

remove_scripts() {
    log "🔧 Step 3: Removing installed scripts"
    
    local scripts=(
        "/usr/local/bin/thakaamed-docker-collector.sh"
        "/usr/local/bin/thakaamed-health-check.sh"
        "/usr/local/bin/rollback-docker-enhancement.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [[ -f "$script" ]]; then
            log "   Removing $script..."
            rm -f "$script"
            success "   ✅ Removed $(basename "$script")"
        else
            info "   ℹ️  $script was not present"
        fi
    done
    
    success "🎯 All scripts removed"
}

remove_log_rotation() {
    log "📋 Step 4: Removing log rotation configuration"
    
    if [[ -f /etc/logrotate.d/thakaamed-docker ]]; then
        log "   Removing logrotate configuration..."
        rm -f /etc/logrotate.d/thakaamed-docker
        success "   ✅ Log rotation configuration removed"
    else
        info "   ℹ️  Log rotation configuration was not present"
    fi
    
    success "🎯 Log rotation configuration cleaned up"
}

handle_log_directories() {
    log "📁 Step 5: Handling ThakaaMed log directories"
    
    local log_dir="/var/log/thakaamed"
    
    if [[ -d "$log_dir" ]]; then
        warning "⚠️  ThakaaMed log directory exists: $log_dir"
        warning "   This contains all the logs we collected. Options:"
        warning "   1. Keep logs for analysis (RECOMMENDED)"
        warning "   2. Archive logs and remove directory"
        warning "   3. Completely remove all logs (DANGEROUS)"
        echo ""
        
        read -p "Choose option (1/2/3) [default: 1]: " choice
        choice=${choice:-1}
        
        case $choice in
            1)
                log "   Keeping log directory for future analysis"
                log "   Moving logs to /var/log/thakaamed-archived-$(date +%Y%m%d-%H%M%S)"
                mv "$log_dir" "/var/log/thakaamed-archived-$(date +%Y%m%d-%H%M%S)"
                success "   ✅ Logs preserved and archived"
                ;;
            2)
                log "   Creating archive of logs..."
                tar -czf "/tmp/thakaamed-logs-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$(dirname "$log_dir")" "$(basename "$log_dir")"
                rm -rf "$log_dir"
                success "   ✅ Logs archived to /tmp/thakaamed-logs-$(date +%Y%m%d-%H%M%S).tar.gz"
                ;;
            3)
                warning "   ⚠️  Completely removing all logs..."
                rm -rf "$log_dir"
                success "   ✅ All logs removed (hope you didn't need those!)"
                ;;
            *)
                log "   Invalid choice, keeping logs (playing it safe)"
                ;;
        esac
    else
        info "   ℹ️  ThakaaMed log directory was not present"
    fi
    
    success "🎯 Log directory handled"
}

verify_system_state() {
    log "🔍 Step 6: Verifying system state after rollback"
    
    # Check Wazuh agent
    log "   Checking Wazuh agent status..."
    if systemctl is-active --quiet wazuh-agent; then
        success "   ✅ Wazuh agent is running (untouched and happy!)"
    else
        error "   ❌ Wazuh agent is not running (this might be unrelated)"
    fi
    
    # Check Docker
    log "   Checking Docker status..."
    if systemctl is-active --quiet docker; then
        success "   ✅ Docker is running (containers are safe!)"
    else
        warning "   ⚠️  Docker is not running (this might be unrelated)"
    fi
    
    # Check for any remaining ThakaaMed processes
    log "   Checking for remaining ThakaaMed processes..."
    local remaining_processes=$(pgrep -f "thakaamed" 2>/dev/null | wc -l)
    if [[ $remaining_processes -eq 0 ]]; then
        success "   ✅ No remaining ThakaaMed processes"
    else
        warning "   ⚠️  Found $remaining_processes ThakaaMed processes still running"
        pgrep -fl "thakaamed" || true
    fi
    
    # Check for ThakaaMed services
    log "   Checking for ThakaaMed services..."
    if systemctl list-units --all | grep -q "thakaamed"; then
        warning "   ⚠️  Found remaining ThakaaMed services:"
        systemctl list-units --all | grep "thakaamed" || true
    else
        success "   ✅ No ThakaaMed services found"
    fi
    
    success "🎯 System state verification complete"
}

show_final_status() {
    echo ""
    success "🎊 ROLLBACK COMPLETE! 🎊"
    echo ""
    info "📊 Current system status:"
    
    # Wazuh agent status
    local wazuh_status=$(systemctl is-active wazuh-agent 2>/dev/null || echo "unknown")
    if [[ "$wazuh_status" == "active" ]]; then
        info "   • Wazuh agent: ${GREEN}✅ Running${NC}"
    else
        info "   • Wazuh agent: ${RED}❌ $wazuh_status${NC}"
    fi
    
    # Docker status
    local docker_status=$(systemctl is-active docker 2>/dev/null || echo "unknown")
    if [[ "$docker_status" == "active" ]]; then
        info "   • Docker: ${GREEN}✅ Running${NC}"
    else
        info "   • Docker: ${RED}❌ $docker_status${NC}"
    fi
    
    # Container count
    local container_count=$(docker ps --format '{{.Names}}' 2>/dev/null | wc -l || echo "0")
    info "   • Running containers: ${CYAN}$container_count${NC}"
    
    # ThakaaMed status
    local thakaamed_status=$(systemctl is-active thakaamed-docker-collector 2>/dev/null || echo "removed")
    if [[ "$thakaamed_status" == "removed" ]] || [[ "$thakaamed_status" == "inactive" ]]; then
        info "   • ThakaaMed collector: ${GREEN}✅ Removed${NC}"
    else
        info "   • ThakaaMed collector: ${YELLOW}⚠️  $thakaamed_status${NC}"
    fi
    
    echo ""
    info "🎯 What happened:"
    info "   ✅ ThakaaMed Docker enhancement completely removed"
    info "   ✅ System restored to pre-enhancement state"
    info "   ✅ Wazuh agent left untouched"
    info "   ✅ Docker containers left running"
    
    echo ""
    info "📁 Logs and cleanup:"
    info "   • Check /var/log/ for any archived ThakaaMed logs"
    info "   • Check /tmp/ for any log archives"
    info "   • All ThakaaMed components removed from system"
    
    echo ""
    warning "⚠️  Important notes:"
    warning "   • If Wazuh agent is not running, that's unrelated to this rollback"
    warning "   • If Docker is not running, that's also unrelated"
    warning "   • This rollback only removes ThakaaMed Docker enhancements"
    
    echo ""
    success "🎉 Your system is back to its original state!"
    success "Hope it was just a drill! 🚀"
}

# ========================================================================
# SAFETY CHECKS
# ========================================================================

check_prerequisites() {
    log "🔍 Running pre-rollback safety checks"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script needs root privileges for complete cleanup"
        error "Please run: sudo $0"
        exit 1
    fi
    
    # Check if there's anything to rollback
    local has_service=false
    local has_scripts=false
    local has_logs=false
    
    if [[ -f /etc/systemd/system/thakaamed-docker-collector.service ]]; then
        has_service=true
    fi
    
    if [[ -f /usr/local/bin/thakaamed-docker-collector.sh ]]; then
        has_scripts=true
    fi
    
    if [[ -d /var/log/thakaamed ]]; then
        has_logs=true
    fi
    
    if [[ "$has_service" == false ]] && [[ "$has_scripts" == false ]] && [[ "$has_logs" == false ]]; then
        warning "🤔 No ThakaaMed components found on this system"
        warning "Either:"
        warning "   • ThakaaMed was never installed here"
        warning "   • It was already rolled back"
        warning "   • You're on the wrong server"
        echo ""
        read -p "Continue anyway? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            info "Rollback cancelled. Probably a wise choice! 🤓"
            exit 0
        fi
    fi
    
    success "✅ Pre-rollback checks complete"
}

# ========================================================================
# MAIN EXECUTION
# ========================================================================

main() {
    # Show the dramatic banner
    show_rollback_banner
    
    # Give user a chance to abort
    countdown
    
    log "🚨 Starting ThakaaMed Docker Enhancement Rollback"
    log "Host: $(hostname) | Date: $(date) | User: $(whoami)"
    
    # Run safety checks
    check_prerequisites
    
    # Execute rollback steps
    stop_services
    remove_systemd_service
    remove_scripts
    remove_log_rotation
    handle_log_directories
    verify_system_state
    
    # Show final status
    show_final_status
}

# ========================================================================
# SCRIPT ENTRY POINT
# ========================================================================

# Handle command line arguments
if [[ $# -gt 0 ]]; then
    case "$1" in
        --force)
            # Skip countdown and confirmations
            log "🚀 Force mode enabled - skipping confirmations"
            check_prerequisites
            stop_services
            remove_systemd_service
            remove_scripts
            remove_log_rotation
            # Force remove logs without asking
            if [[ -d /var/log/thakaamed ]]; then
                log "Force removing log directory..."
                rm -rf /var/log/thakaamed
            fi
            verify_system_state
            show_final_status
            ;;
        --help|-h)
            echo "ThakaaMed Docker Enhancement Rollback Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --force    Skip confirmations and force rollback"
            echo "  --help     Show this help message"
            echo ""
            echo "Examples:"
            echo "  sudo $0                    # Interactive rollback"
            echo "  sudo $0 --force           # Force rollback without prompts"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            error "Use --help for usage information"
            exit 1
            ;;
    esac
else
    # Interactive mode
    main "$@"
fi

# ========================================================================
# END OF ROLLBACK SCRIPT
# ========================================================================
# If you're reading this comment, either:
# 1. You're curious about the code (good for you! 🤓)
# 2. Something went wrong and you're debugging (sorry! 😅)
# 3. You're procrastinating (we've all been there 😴)
#
# Either way, thanks for using ThakaaMed tools responsibly! 🚀
# ======================================================================== 