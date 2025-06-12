#!/bin/bash
# ========================================================================
# ThakaaMed Health Check Script
# ========================================================================
# 
# 🩺 Like a doctor, but for your Docker monitoring system!
# 
# This script performs comprehensive health checks on your ThakaaMed
# Docker monitoring setup. Think of it as a full medical examination
# for your container monitoring infrastructure.
#
# What it checks:
# - Service health (is everything running?)
# - Log file activity (are logs flowing?)
# - Disk space (do we have room for more logs?)
# - Docker connectivity (can we talk to Docker?)
# - Wazuh agent health (is the agent happy?)
# - Performance metrics (how are we doing?)
#
# ========================================================================

set -euo pipefail

# Colors for beautiful output 🎨
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
LOG_DIR="/var/log/thakaamed"
SERVICE_NAME="thakaamed-docker-collector"
WAZUH_SERVICE="wazuh-agent"
DOCKER_SERVICE="docker"

# ========================================================================
# UTILITY FUNCTIONS
# ========================================================================

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# Health check result tracking
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

record_result() {
    local status=$1
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    case $status in
        "pass")
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            ;;
        "fail")
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            ;;
        "warning")
            WARNING_CHECKS=$((WARNING_CHECKS + 1))
            ;;
    esac
}

# ========================================================================
# HEALTH CHECK FUNCTIONS
# ========================================================================

show_banner() {
    echo -e "${PURPLE}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                🩺 ThakaaMed Health Check 🩺                   ║"
    echo "║                                                              ║"
    echo "║        \"Checking the pulse of your monitoring system\"        ║"
    echo "║                                                              ║"
    echo "║              Time: $(date +'%Y-%m-%d %H:%M:%S')                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if services are running
check_services() {
    echo -e "${BOLD}🔧 SERVICE HEALTH CHECKS${NC}"
    echo "=============================================="
    
    # Check ThakaaMed Docker Collector
    log "Checking ThakaaMed Docker Collector service..."
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        local uptime=$(systemctl show "$SERVICE_NAME" --property=ActiveEnterTimestamp | cut -d= -f2)
        success "ThakaaMed Docker Collector is running (since $uptime)"
        record_result "pass"
    else
        error "ThakaaMed Docker Collector is not running"
        info "Try: sudo systemctl start $SERVICE_NAME"
        record_result "fail"
    fi
    
    # Check Wazuh Agent
    log "Checking Wazuh agent service..."
    if systemctl is-active --quiet "$WAZUH_SERVICE" 2>/dev/null; then
        local wazuh_status=$(/var/ossec/bin/wazuh-control status 2>/dev/null | grep -c "is running" || echo "0")
        if [[ $wazuh_status -gt 3 ]]; then
            success "Wazuh agent is running with $wazuh_status processes"
            record_result "pass"
        else
            warning "Wazuh agent service is active but some processes may be down"
            record_result "warning"
        fi
    else
        error "Wazuh agent is not running"
        info "Try: sudo systemctl start $WAZUH_SERVICE"
        record_result "fail"
    fi
    
    # Check Docker
    log "Checking Docker service..."
    if systemctl is-active --quiet "$DOCKER_SERVICE" 2>/dev/null; then
        local container_count=$(docker ps --format '{{.Names}}' 2>/dev/null | wc -l || echo "0")
        success "Docker is running with $container_count active containers"
        record_result "pass"
    else
        error "Docker service is not running"
        info "Try: sudo systemctl start $DOCKER_SERVICE"
        record_result "fail"
    fi
    
    echo ""
}

# Check log file activity
check_log_activity() {
    echo -e "${BOLD}📁 LOG ACTIVITY CHECKS${NC}"
    echo "=============================================="
    
    # Check if log directory exists
    log "Checking ThakaaMed log directory..."
    if [[ -d "$LOG_DIR" ]]; then
        success "ThakaaMed log directory exists: $LOG_DIR"
        record_result "pass"
    else
        error "ThakaaMed log directory not found: $LOG_DIR"
        record_result "fail"
        return
    fi
    
    # Check for recent log files
    log "Checking for recent log activity..."
    local recent_logs=$(find "$LOG_DIR" -name "*.log" -mmin -10 2>/dev/null | wc -l)
    if [[ $recent_logs -gt 0 ]]; then
        success "Found $recent_logs log files updated in last 10 minutes"
        record_result "pass"
    else
        warning "No recent log activity (files older than 10 minutes)"
        info "This might be normal if containers are quiet"
        record_result "warning"
    fi
    
    # Check log file sizes
    log "Checking log file sizes..."
    local large_logs=$(find "$LOG_DIR" -name "*.log" -size +100M 2>/dev/null | wc -l)
    if [[ $large_logs -eq 0 ]]; then
        success "No excessively large log files found"
        record_result "pass"
    else
        warning "Found $large_logs log files larger than 100MB"
        info "Consider checking log rotation configuration"
        record_result "warning"
    fi
    
    # Check for critical alerts
    log "Checking for critical security alerts..."
    local critical_alerts=0
    if [[ -f "$LOG_DIR/security/CRITICAL-ALERTS.log" ]]; then
        critical_alerts=$(wc -l < "$LOG_DIR/security/CRITICAL-ALERTS.log" 2>/dev/null || echo "0")
    fi
    
    if [[ $critical_alerts -eq 0 ]]; then
        success "No critical security alerts found"
        record_result "pass"
    else
        error "Found $critical_alerts critical security alerts!"
        info "Check: $LOG_DIR/security/CRITICAL-ALERTS.log"
        record_result "fail"
    fi
    
    echo ""
}

# Check disk space
check_disk_space() {
    echo -e "${BOLD}💾 DISK SPACE CHECKS${NC}"
    echo "=============================================="
    
    log "Checking disk space for log directory..."
    local usage=$(df "$LOG_DIR" 2>/dev/null | awk 'NR==2 {print $5}' | sed 's/%//' || echo "100")
    local available=$(df -h "$LOG_DIR" 2>/dev/null | awk 'NR==2 {print $4}' || echo "unknown")
    
    if [[ $usage -lt 80 ]]; then
        success "Disk space OK (${usage}% used, $available available)"
        record_result "pass"
    elif [[ $usage -lt 90 ]]; then
        warning "Disk space getting high (${usage}% used, $available available)"
        info "Consider cleaning up old logs or increasing disk space"
        record_result "warning"
    else
        error "Disk space critically low (${usage}% used, $available available)"
        info "Immediate action required - clean up logs or add disk space"
        record_result "fail"
    fi
    
    # Check log directory size
    log "Checking ThakaaMed log directory size..."
    local log_size=$(du -sh "$LOG_DIR" 2>/dev/null | cut -f1 || echo "unknown")
    if [[ "$log_size" != "unknown" ]]; then
        info "ThakaaMed logs currently using: $log_size"
        
        # Convert to MB for comparison (rough estimate)
        local size_mb=$(du -sm "$LOG_DIR" 2>/dev/null | cut -f1 || echo "0")
        if [[ $size_mb -lt 1024 ]]; then  # Less than 1GB
            success "Log directory size is reasonable (${log_size})"
            record_result "pass"
        elif [[ $size_mb -lt 5120 ]]; then  # Less than 5GB
            warning "Log directory is getting large (${log_size})"
            record_result "warning"
        else
            error "Log directory is very large (${log_size})"
            info "Consider archiving or cleaning up old logs"
            record_result "fail"
        fi
    fi
    
    echo ""
}

# Check Docker connectivity and container health
check_docker_health() {
    echo -e "${BOLD}🐳 DOCKER HEALTH CHECKS${NC}"
    echo "=============================================="
    
    # Check Docker daemon connectivity
    log "Testing Docker daemon connectivity..."
    if docker info >/dev/null 2>&1; then
        success "Docker daemon is responsive"
        record_result "pass"
    else
        error "Cannot connect to Docker daemon"
        info "Check Docker service and permissions"
        record_result "fail"
        return
    fi
    
    # Check running containers
    log "Checking container status..."
    local total_containers=$(docker ps -a --format '{{.Names}}' 2>/dev/null | wc -l || echo "0")
    local running_containers=$(docker ps --format '{{.Names}}' 2>/dev/null | wc -l || echo "0")
    local unhealthy_containers=$(docker ps --filter "health=unhealthy" --format '{{.Names}}' 2>/dev/null | wc -l || echo "0")
    
    if [[ $running_containers -gt 0 ]]; then
        success "$running_containers/$total_containers containers are running"
        record_result "pass"
    else
        warning "No containers are currently running"
        record_result "warning"
    fi
    
    if [[ $unhealthy_containers -eq 0 ]]; then
        success "No unhealthy containers detected"
        record_result "pass"
    else
        error "$unhealthy_containers containers are unhealthy"
        info "Check container logs for issues"
        record_result "fail"
    fi
    
    # Check for containers we're monitoring
    log "Checking monitored containers..."
    if [[ -d "$LOG_DIR/docker" ]]; then
        local monitored_containers=$(ls "$LOG_DIR/docker"/*.log 2>/dev/null | wc -l || echo "0")
        if [[ $monitored_containers -gt 0 ]]; then
            success "Monitoring logs for $monitored_containers containers"
            record_result "pass"
        else
            warning "No container log files found"
            record_result "warning"
        fi
    fi
    
    echo ""
}

# Check system performance
check_performance() {
    echo -e "${BOLD}📊 PERFORMANCE CHECKS${NC}"
    echo "=============================================="
    
    # Check system load
    log "Checking system load..."
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    local cpu_cores=$(nproc)
    local load_per_core=$(echo "$load_avg / $cpu_cores" | bc -l 2>/dev/null | awk '{printf "%.2f", $0}' || echo "unknown")
    
    if [[ "$load_per_core" != "unknown" ]] && (( $(echo "$load_per_core < 0.8" | bc -l) )); then
        success "System load is normal ($load_avg on $cpu_cores cores)"
        record_result "pass"
    elif [[ "$load_per_core" != "unknown" ]] && (( $(echo "$load_per_core < 1.5" | bc -l) )); then
        warning "System load is elevated ($load_avg on $cpu_cores cores)"
        record_result "warning"
    else
        error "System load is high ($load_avg on $cpu_cores cores)"
        record_result "fail"
    fi
    
    # Check memory usage
    log "Checking memory usage..."
    local mem_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    if [[ $mem_usage -lt 80 ]]; then
        success "Memory usage is normal (${mem_usage}%)"
        record_result "pass"
    elif [[ $mem_usage -lt 90 ]]; then
        warning "Memory usage is high (${mem_usage}%)"
        record_result "warning"
    else
        error "Memory usage is critical (${mem_usage}%)"
        record_result "fail"
    fi
    
    # Check ThakaaMed collector resource usage
    log "Checking ThakaaMed collector resource usage..."
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        local collector_pid=$(systemctl show "$SERVICE_NAME" --property=MainPID | cut -d= -f2)
        if [[ "$collector_pid" != "0" ]] && [[ -n "$collector_pid" ]]; then
            local cpu_usage=$(ps -p "$collector_pid" -o %cpu --no-headers 2>/dev/null | awk '{print $1}' || echo "0")
            local mem_usage=$(ps -p "$collector_pid" -o %mem --no-headers 2>/dev/null | awk '{print $1}' || echo "0")
            
            success "Collector using ${cpu_usage}% CPU, ${mem_usage}% memory"
            record_result "pass"
        else
            warning "Could not get collector resource usage"
            record_result "warning"
        fi
    fi
    
    echo ""
}

# Check network connectivity
check_connectivity() {
    echo -e "${BOLD}🌐 CONNECTIVITY CHECKS${NC}"
    echo "=============================================="
    
    # Check if we can resolve hostnames
    log "Checking DNS resolution..."
    if nslookup google.com >/dev/null 2>&1; then
        success "DNS resolution is working"
        record_result "pass"
    else
        warning "DNS resolution issues detected"
        record_result "warning"
    fi
    
    # Check Wazuh manager connectivity (if we can determine the manager IP)
    log "Checking Wazuh manager connectivity..."
    local manager_ip=$(grep "server>" /var/ossec/etc/ossec.conf 2>/dev/null | sed 's/.*>\(.*\)<.*/\1/' | head -1 || echo "")
    if [[ -n "$manager_ip" ]] && [[ "$manager_ip" != "" ]]; then
        if ping -c 1 "$manager_ip" >/dev/null 2>&1; then
            success "Can reach Wazuh manager at $manager_ip"
            record_result "pass"
        else
            error "Cannot reach Wazuh manager at $manager_ip"
            record_result "fail"
        fi
    else
        warning "Could not determine Wazuh manager IP"
        record_result "warning"
    fi
    
    echo ""
}

# Generate health report summary
show_health_summary() {
    echo -e "${BOLD}📋 HEALTH CHECK SUMMARY${NC}"
    echo "=============================================="
    
    local success_rate=0
    if [[ $TOTAL_CHECKS -gt 0 ]]; then
        success_rate=$(echo "scale=1; $PASSED_CHECKS * 100 / $TOTAL_CHECKS" | bc -l 2>/dev/null || echo "0")
    fi
    
    echo -e "Total Checks: ${BOLD}$TOTAL_CHECKS${NC}"
    echo -e "Passed: ${GREEN}$PASSED_CHECKS${NC}"
    echo -e "Warnings: ${YELLOW}$WARNING_CHECKS${NC}"
    echo -e "Failed: ${RED}$FAILED_CHECKS${NC}"
    echo -e "Success Rate: ${BOLD}${success_rate}%${NC}"
    echo ""
    
    # Overall health status
    if [[ $FAILED_CHECKS -eq 0 ]] && [[ $WARNING_CHECKS -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}🎉 OVERALL STATUS: EXCELLENT${NC}"
        echo "Your ThakaaMed monitoring system is in perfect health!"
    elif [[ $FAILED_CHECKS -eq 0 ]]; then
        echo -e "${YELLOW}${BOLD}⚠️  OVERALL STATUS: GOOD WITH WARNINGS${NC}"
        echo "Your system is working but has some areas for improvement."
    elif [[ $FAILED_CHECKS -lt 3 ]]; then
        echo -e "${RED}${BOLD}🚨 OVERALL STATUS: NEEDS ATTENTION${NC}"
        echo "Your system has some issues that should be addressed."
    else
        echo -e "${RED}${BOLD}💥 OVERALL STATUS: CRITICAL${NC}"
        echo "Your system has serious issues that need immediate attention!"
    fi
    
    echo ""
    
    # Recommendations
    if [[ $WARNING_CHECKS -gt 0 ]] || [[ $FAILED_CHECKS -gt 0 ]]; then
        echo -e "${BOLD}💡 RECOMMENDATIONS:${NC}"
        
        if [[ $FAILED_CHECKS -gt 0 ]]; then
            echo "• Fix failed checks first - they indicate serious issues"
            echo "• Check service logs: journalctl -u thakaamed-docker-collector"
            echo "• Verify Wazuh agent logs: tail -f /var/ossec/logs/ossec.log"
        fi
        
        if [[ $WARNING_CHECKS -gt 0 ]]; then
            echo "• Address warnings to prevent future issues"
            echo "• Monitor disk space and clean up old logs if needed"
            echo "• Consider optimizing system resources"
        fi
        
        echo "• Run this health check regularly to track improvements"
        echo "• Use 'sudo /usr/local/bin/rollback-docker-enhancement.sh' if issues persist"
    fi
    
    echo ""
}

# ========================================================================
# MAIN EXECUTION
# ========================================================================

main() {
    show_banner
    
    log "Starting comprehensive health check..."
    log "Host: $(hostname) | User: $(whoami)"
    echo ""
    
    # Run all health checks
    check_services
    check_log_activity
    check_disk_space
    check_docker_health
    check_performance
    check_connectivity
    
    # Show summary
    show_health_summary
    
    # Exit with appropriate code
    if [[ $FAILED_CHECKS -eq 0 ]]; then
        exit 0  # Success
    else
        exit 1  # Issues found
    fi
}

# ========================================================================
# COMMAND LINE INTERFACE
# ========================================================================

case "${1:-}" in
    --help|-h)
        echo "ThakaaMed Health Check Script"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --quick, -q    Run quick health check (basic checks only)"
        echo "  --verbose, -v  Show verbose output with detailed information"
        echo ""
        echo "Examples:"
        echo "  $0                # Run full health check"
        echo "  $0 --quick       # Run quick health check"
        echo "  $0 --verbose     # Run with verbose output"
        exit 0
        ;;
    --quick|-q)
        # Quick mode - just check if services are running
        echo "🚀 Quick Health Check"
        echo "===================="
        check_services
        if [[ $FAILED_CHECKS -eq 0 ]]; then
            success "Quick check passed - all services are running!"
        else
            error "Quick check failed - $FAILED_CHECKS services have issues"
        fi
        exit $FAILED_CHECKS
        ;;
    --verbose|-v)
        # Verbose mode - show extra debugging info
        set -x
        main "$@"
        ;;
    "")
        # Normal mode
        main "$@"
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac

# ========================================================================
# END OF HEALTH CHECK SCRIPT
# ========================================================================
# If you've made it this far, congratulations! 🎉
# 
# You've either:
# 1. Successfully run a health check (awesome!)
# 2. Read through the entire script (impressive!)
# 3. Are debugging an issue (we feel your pain)
# 
# Either way, remember: A healthy monitoring system is a happy 
# monitoring system. And happy monitoring systems catch bad guys! 👮‍♂️
# ======================================================================== 