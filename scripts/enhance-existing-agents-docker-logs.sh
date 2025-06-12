#!/bin/bash
# ========================================================================
# ThakaaMed Docker Log Enhancement for Existing Wazuh Agents
# ========================================================================
# 
# 🎭 What does this script do?
# - Takes your boring, vanilla Wazuh agent and turns it into a 
#   Docker-monitoring superhero! 🦸‍♂️
# - Adds comprehensive Docker log collection without breaking anything
# - Makes your DevOps team happy (a rare achievement!)
# - Catches "fishy" activities because we're all about that bass... I mean security! 🐠
#
# 🚨 What this script does NOT do:
# - Install Wazuh (that's already done, right?)
# - Make coffee (though we wish it could ☕)
# - Fix your relationship problems
# - Understand why Docker containers randomly die at 3 AM
#
# 📋 Prerequisites:
# - Existing Wazuh agent (duh!)
# - Docker installed and running
# - Root privileges (because we're fancy like that)
# - A sense of humor (optional but recommended)
#
# 🎯 Compatible with:
# - Raspberry Pi (our test subject)
# - Ubuntu/Debian servers
# - Any Linux box that doesn't hate Docker
#
# ========================================================================

set -euo pipefail  # Because we're professionals, not cowboys 🤠

# ========================================================================
# CONFIGURATION SECTION
# ========================================================================
# Feel free to modify these if you know what you're doing.
# If you don't know what you're doing, maybe ask ChatGPT? 🤖

# Where the magic happens - our standardized log directory
LOG_DIR="/var/log/thakaamed"

# Suspicious patterns - because paranoia is just good security practice
SUSPICIOUS_PATTERNS="password|login|auth|fail|error|unauthorized|denied|attack|hack|exploit|injection|xss|traversal|breach|malware|suspicious|anomaly"

# Colors for pretty output (because life is too short for boring logs)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ========================================================================
# UTILITY FUNCTIONS
# ========================================================================
# These functions are like Swiss Army knives, but for bash scripts

# Logging function with more personality than a WordPress blog
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

# Error function - for when things go sideways (and they will)
error() {
    echo -e "${RED}[ERROR - OH NO!]${NC} $1" >&2
}

# Warning function - like your mother, but for scripts
warning() {
    echo -e "${YELLOW}[WARNING - HEADS UP!]${NC} $1"
}

# Info function - for those "did you know?" moments
info() {
    echo -e "${BLUE}[INFO - FYI]${NC} $1"
}

# Success function - for when we actually get something right
success() {
    echo -e "${CYAN}[SUCCESS - BOOM! 💥]${NC} $1"
}

# Banner function - because we're dramatic like that
show_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║        🏥 ThakaaMed Docker Log Enhancement v2.0 🐳           ║"
    echo "║                                                              ║"
    echo "║  Making your Wazuh agent smarter, one container at a time   ║"
    echo "║                                                              ║"
    echo "║  Warning: May cause sudden improvements in security! 🚀     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ========================================================================
# SAFETY CHECKS
# ========================================================================
# Because we learned from our mistakes (the hard way)

check_prerequisites() {
    log "Running safety checks (because we're responsible adults) 🧐"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script needs root privileges. Try: sudo $0"
        error "No, 'please' doesn't work. We tried. 🙄"
        exit 1
    fi
    
    # Check if Wazuh agent exists
    if ! systemctl list-units --full -all | grep -Fq "wazuh-agent.service"; then
        error "Wazuh agent not found! This script is for EXISTING agents."
        error "If you need a fresh install, you want the full deployment script."
        error "It's like trying to upgrade a car that doesn't exist. 🚗❌"
        exit 1
    fi
    
    # Check if Wazuh agent is running
    if ! systemctl is-active --quiet wazuh-agent; then
        error "Wazuh agent is not running! Fix that first."
        error "It's like trying to tune a radio that's not plugged in. 📻"
        exit 1
    fi
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        error "Docker not found! No Docker = No Docker logs. Mind blown! 🤯"
        exit 1
    fi
    
    # Check if Docker is running
    if ! systemctl is-active --quiet docker; then
        error "Docker service is not running. Please start it first."
        error "sudo systemctl start docker  # There, I did the work for you 😉"
        exit 1
    fi
    
    # Check if jq is available (because JSON without jq is like pizza without cheese)
    if ! command -v jq &> /dev/null; then
        warning "jq not found. Installing it because JSON parsing without jq is painful."
        apt-get update -qq && apt-get install -y jq
    fi
    
    success "All prerequisites check out! Ready to rock and roll! 🎸"
}

# ========================================================================
# DIRECTORY CREATION
# ========================================================================
# Creating the folder structure that makes DevOps teams happy

create_thakaamed_structure() {
    log "Creating ThakaaMed directory structure (the DevOps approved way) 📁"
    
    # Create the main directories
    mkdir -p "$LOG_DIR"/{docker,application,security,api,medical,system,archive}
    
    # Set proper permissions (because security matters)
    chown -R root:root "$LOG_DIR"
    chmod -R 755 "$LOG_DIR"
    
    # Create subdirectories for better organization
    mkdir -p "$LOG_DIR/docker/containers"
    mkdir -p "$LOG_DIR/application/"{web,api,background}
    mkdir -p "$LOG_DIR/security/"{alerts,violations,suspicious}
    mkdir -p "$LOG_DIR/system/"{events,performance,errors}
    
    info "Directory structure created. Your DevOps team will love you! ❤️"
    info "Or at least hate you less. Progress! 📈"
}

# ========================================================================
# DOCKER LOG COLLECTOR SCRIPT
# ========================================================================
# The star of the show - where the magic happens

create_docker_collector() {
    log "Creating the Docker log collector script (the brain of the operation) 🧠"
    
    cat > /usr/local/bin/thakaamed-docker-collector.sh << 'COLLECTOR_SCRIPT'
#!/bin/bash
# ========================================================================
# ThakaaMed Docker Log Collector
# ========================================================================
# This script is like a digital detective - it watches everything,
# remembers everything, and occasionally gets paranoid about nothing.
# But hey, that's cybersecurity for you! 🕵️‍♂️

LOG_DIR="/var/log/thakaamed"
SUSPICIOUS_PATTERNS="password|login|auth|fail|error|unauthorized|denied|attack|hack|exploit|injection|xss|traversal|breach|malware|suspicious|anomaly"

# ========================================================================
# LOGGING FUNCTIONS
# ========================================================================

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/system/docker-collector.log"
}

# ========================================================================
# JSON FORMATTING FOR DEVOPS
# ========================================================================
# Because DevOps teams have strong opinions about log formats
# (And we respect their opinions... mostly)

format_for_devops() {
    local container=$1
    local app_type=$2
    local message=$3
    local level=${4:-"info"}
    local source=${5:-"docker"}
    
    # Clean the message to prevent JSON breakage
    # Because broken JSON makes DevOps teams cry 😢
    local clean_message=$(echo "$message" | sed 's/"/\\"/g' | sed 's/\t/ /g' | tr -d '\000-\037')
    
    jq -n \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg container "$container" \
        --arg app "$app_type" \
        --arg msg "$clean_message" \
        --arg host "$(hostname)" \
        --arg env "production" \
        --arg service "thakaamed" \
        --arg level "$level" \
        --arg source "$source" \
        --arg agent_id "$(hostname | tr -d '.-' | tail -c 4)" \
        --arg location "$(hostname)" \
        '{
            "@timestamp": $ts,
            "container": $container,
            "application": $app,
            "message": $msg,
            "host": $host,
            "environment": $env,
            "service": $service,
            "docker": true,
            "level": $level,
            "source": $source,
            "agent_id": $agent_id,
            "location": $location,
            "thakaamed_version": "2.0"
        }'
}

# ========================================================================
# APPLICATION TYPE DETECTION
# ========================================================================
# Our app categorization system - like a sommelier, but for containers

detect_app_type() {
    local container=$1
    local env_vars=$(docker inspect "$container" 2>/dev/null | jq -r '.[0].Config.Env[]' 2>/dev/null || echo "")
    local image=$(docker inspect "$container" 2>/dev/null | jq -r '.[0].Config.Image' 2>/dev/null || echo "")
    local ports=$(docker inspect "$container" 2>/dev/null | jq -r '.[0].NetworkSettings.Ports | keys[]' 2>/dev/null || echo "")
    
    # Medical applications (the VIPs)
    if echo "$env_vars" | grep -q "DJANGO_SETTINGS_MODULE"; then
        echo "medical-django"
    elif echo "$env_vars" | grep -q "FASTAPI"; then
        echo "medical-api"
    elif echo "$image" | grep -iq "medical\|hospital\|patient\|dicom"; then
        echo "medical-service"
    
    # Monitoring stack (the watchers)
    elif echo "$image" | grep -q "grafana"; then
        echo "monitoring-grafana"
    elif echo "$image" | grep -q "prometheus"; then
        echo "monitoring-prometheus"
    elif echo "$image" | grep -q "uptime-kuma"; then
        echo "monitoring-uptime"
    elif echo "$image" | grep -q "node-exporter"; then
        echo "monitoring-metrics"
    elif echo "$image" | grep -q "alertmanager"; then
        echo "monitoring-alerts"
    
    # Databases (the memory keepers)
    elif echo "$image" | grep -iq "postgres\|mysql\|mongo\|redis"; then
        echo "database-service"
    
    # Web servers (the front-line workers)
    elif echo "$image" | grep -iq "nginx\|apache\|httpd"; then
        echo "web-server"
    
    # The "I have no idea what this is" category
    else
        echo "unknown-service"
    fi
}

# ========================================================================
# SUSPICIOUS ACTIVITY DETECTION
# ========================================================================
# Our paranoia engine - because in cybersecurity, paranoia is a feature!

check_suspicious_activity() {
    local message=$1
    local container=$2
    local app_type=$3
    
    # Check for suspicious patterns
    if echo "$message" | grep -iE "$SUSPICIOUS_PATTERNS" >/dev/null; then
        local threat_level="warning"
        
        # Escalate threat level for certain patterns
        if echo "$message" | grep -iE "hack|exploit|breach|malware|injection" >/dev/null; then
            threat_level="critical"
        fi
        
        local alert=$(format_for_devops "$container" "$app_type" "$message" "$threat_level" "security-alert")
        echo "$alert" >> "$LOG_DIR/security/suspicious-activity.log"
        
        # Also log to container-specific security log
        echo "$alert" >> "$LOG_DIR/security/alerts/${container}-security.log"
        
        log "🚨 SECURITY ALERT [$threat_level]: Suspicious activity in $container"
        
        # For critical threats, also create an immediate alert file
        if [[ "$threat_level" == "critical" ]]; then
            echo "$alert" >> "$LOG_DIR/security/CRITICAL-ALERTS.log"
            log "🔥 CRITICAL THREAT DETECTED! Check $LOG_DIR/security/CRITICAL-ALERTS.log"
        fi
        
        return 0
    fi
    return 1
}

# ========================================================================
# CONTAINER LOG COLLECTION
# ========================================================================
# The main event - where we actually collect the logs

collect_container_logs() {
    local container=$1
    local app_type=$2
    local log_file="$LOG_DIR/docker/${app_type}-${container}.log"
    
    log "🎯 Starting log collection for $container (type: $app_type)"
    
    # Create container-specific directories
    mkdir -p "$LOG_DIR/docker/containers/$container"
    mkdir -p "$LOG_DIR/security/alerts"
    
    # Create container-specific log file
    touch "$log_file"
    
    # Stream container logs with timestamps
    # This is where the magic happens! ✨
    docker logs -f --timestamps "$container" 2>&1 | while read -r line; do
        # Parse timestamp and message
        if [[ "$line" =~ ^([0-9T:-]+Z?)\s+(.*)$ ]]; then
            timestamp="${BASH_REMATCH[1]}"
            message="${BASH_REMATCH[2]}"
        else
            timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            message="$line"
        fi
        
        # Skip empty messages (because why log nothing?)
        [[ -z "$message" ]] && continue
        
        # Check for suspicious activity (stay vigilant!)
        check_suspicious_activity "$message" "$container" "$app_type"
        
        # Format as DevOps-standard JSON
        formatted_log=$(format_for_devops "$container" "$app_type" "$message")
        echo "$formatted_log" >> "$log_file"
        
        # Route to application-specific logs
        case "$app_type" in
            "medical-"*)
                echo "$formatted_log" >> "$LOG_DIR/medical/medical-apps.log"
                ;;
            "monitoring-"*)
                echo "$formatted_log" >> "$LOG_DIR/application/monitoring.log"
                ;;
            "database-"*)
                echo "$formatted_log" >> "$LOG_DIR/application/database.log"
                ;;
            "web-"*)
                echo "$formatted_log" >> "$LOG_DIR/application/web-servers.log"
                ;;
            *)
                echo "$formatted_log" >> "$LOG_DIR/application/general.log"
                ;;
        esac
        
        # Also save to container-specific directory
        echo "$formatted_log" >> "$LOG_DIR/docker/containers/$container/$(date +%Y-%m-%d).log"
        
    done &
    
    # Store the PID for later management
    echo $! > "/var/run/thakaamed-collector-${container}.pid"
}

# ========================================================================
# DOCKER EVENTS MONITORING
# ========================================================================
# Watching Docker like a hawk watches mice 🦅

monitor_docker_events() {
    log "🔍 Starting Docker events monitoring (Big Brother mode activated)"
    
    docker events --format '{{json .}}' | while read -r event; do
        # Parse Docker event
        local action=$(echo "$event" | jq -r '.Action // "unknown"' 2>/dev/null || echo "unknown")
        local container_name=$(echo "$event" | jq -r '.Actor.Attributes.name // "unknown"' 2>/dev/null || echo "unknown")
        local event_time=$(echo "$event" | jq -r '.time // ""' 2>/dev/null || echo "")
        local event_type=$(echo "$event" | jq -r '.Type // "unknown"' 2>/dev/null || echo "unknown")
        
        # Format Docker event for DevOps
        local formatted_event=$(jq -n \
            --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg action "$action" \
            --arg container "$container_name" \
            --arg host "$(hostname)" \
            --arg event_type "$event_type" \
            --arg raw_event "$event" \
            '{
                "@timestamp": $ts,
                "event_type": "docker_event",
                "action": $action,
                "container": $container,
                "docker_event_type": $event_type,
                "host": $host,
                "service": "thakaamed",
                "docker": true,
                "raw_event": $raw_event,
                "source": "docker-daemon"
            }')
        
        echo "$formatted_event" >> "$LOG_DIR/system/docker-events.log"
        
        # Log significant events
        case "$action" in
            "start")
                log "🟢 Container started: $container_name"
                ;;
            "stop"|"die")
                log "🔴 Container stopped: $container_name"
                ;;
            "kill")
                log "💀 Container killed: $container_name (RIP)"
                ;;
            "restart")
                log "🔄 Container restarted: $container_name"
                ;;
            "create")
                log "🆕 Container created: $container_name"
                ;;
            "destroy")
                log "💥 Container destroyed: $container_name"
                ;;
        esac
    done &
    
    echo $! > "/var/run/thakaamed-docker-events.pid"
}

# ========================================================================
# CONTAINER HEALTH MONITORING
# ========================================================================
# Because sometimes containers lie about being healthy 🤥

monitor_container_health() {
    log "🏥 Starting container health monitoring"
    
    while true; do
        # Get all containers (running and stopped)
        local containers=$(docker ps -a --format '{{.Names}}:{{.Status}}:{{.State}}')
        
        while IFS=':' read -r name status state; do
            [[ -z "$name" ]] && continue
            
            local health_log=$(format_for_devops "$name" "health-check" "Status: $status, State: $state" "info" "health-monitor")
            echo "$health_log" >> "$LOG_DIR/system/container-health.log"
            
            # Alert on unhealthy containers
            if echo "$status" | grep -iq "unhealthy\|exited\|dead"; then
                local alert=$(format_for_devops "$name" "health-alert" "Container unhealthy: $status" "warning" "health-monitor")
                echo "$alert" >> "$LOG_DIR/security/alerts/health-alerts.log"
                log "⚠️  Health alert: $name is $status"
            fi
            
        done <<< "$containers"
        
        # Check every 5 minutes (because we're not THAT paranoid)
        sleep 300
    done &
    
    echo $! > "/var/run/thakaamed-health-monitor.pid"
}

# ========================================================================
# MAIN MONITORING LOOP
# ========================================================================
# The conductor of our orchestra of chaos

main() {
    log "🚀 ThakaaMed Docker Collector starting on $(hostname)"
    log "🎭 Monitoring all containers with DevOps standardization"
    log "🕵️ Suspicious activity detection: ENABLED"
    log "🏥 Health monitoring: ENABLED"
    log "📊 Event monitoring: ENABLED"
    
    # Start Docker events monitoring
    monitor_docker_events
    
    # Start container health monitoring
    monitor_container_health
    
    # Main container monitoring loop
    while true; do
        # Get list of running containers
        mapfile -t containers < <(docker ps --format '{{.Names}}')
        
        log "🔍 Scanning for containers... Found ${#containers[@]} running"
        
        for container in "${containers[@]}"; do
            # Skip if we're already collecting logs for this container
            if [[ -f "/var/run/thakaamed-collector-${container}.pid" ]] && kill -0 "$(cat "/var/run/thakaamed-collector-${container}.pid")" 2>/dev/null; then
                continue  # Already monitoring this one
            fi
            
            app_type=$(detect_app_type "$container")
            log "🆕 New container detected: $container (type: $app_type)"
            collect_container_logs "$container" "$app_type"
        done
        
        # Clean up dead PID files
        for pidfile in /var/run/thakaamed-collector-*.pid; do
            [[ -f "$pidfile" ]] || continue
            local pid=$(cat "$pidfile" 2>/dev/null || echo "")
            if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
                rm -f "$pidfile"
            fi
        done
        
        # Check every 30 seconds for new containers
        sleep 30
    done
}

# ========================================================================
# SIGNAL HANDLERS
# ========================================================================
# Graceful shutdown because we're classy like that

cleanup() {
    log "🛑 Received shutdown signal. Cleaning up..."
    
    # Kill all child processes
    for pidfile in /var/run/thakaamed-*.pid; do
        [[ -f "$pidfile" ]] || continue
        local pid=$(cat "$pidfile" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "🔪 Stopping process $pid"
            kill "$pid" 2>/dev/null || true
        fi
        rm -f "$pidfile"
    done
    
    log "👋 ThakaaMed Docker Collector stopped gracefully"
    exit 0
}

trap cleanup SIGTERM SIGINT

# ========================================================================
# STARTUP
# ========================================================================

# Ensure log directories exist
mkdir -p "$LOG_DIR"/{docker/containers,application,security/alerts,system}

# Start the main function
main "$@"
COLLECTOR_SCRIPT

    # Make it executable (because executable permissions are like trust - earned)
    chmod +x /usr/local/bin/thakaamed-docker-collector.sh
    
    success "Docker collector script created! It's ready to watch everything! 👁️"
}

# ========================================================================
# SYSTEMD SERVICE CREATION
# ========================================================================

create_systemd_service() {
    log "Creating systemd service (because we believe in proper process management) ⚙️"
    
    cat > /etc/systemd/system/thakaamed-docker-collector.service << 'SERVICE_FILE'
[Unit]
Description=ThakaaMed Docker Log Collector - The Watcher of Containers
Documentation=https://thakaamed.com/docs/logging
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/thakaamed-docker-collector.sh
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=thakaamed-docker-collector
User=root
Group=root

# Security settings (because we're paranoid in a good way)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/thakaamed /var/run
PrivateTmp=true

# Resource limits (because even watchers need boundaries)
MemoryLimit=512M
CPUQuota=75%

# Environment variables
Environment=LOG_LEVEL=info
Environment=DOCKER_HOST=unix:///var/run/docker.sock

[Install]
WantedBy=multi-user.target
SERVICE_FILE

    success "Systemd service created! Your system now knows how to babysit our script! 👶"
}

# ========================================================================
# LOG ROTATION SETUP
# ========================================================================

setup_log_rotation() {
    log "Setting up log rotation (because logs without rotation are like hoarding) 🗂️"
    
    cat > /etc/logrotate.d/thakaamed-docker << 'LOGROTATE_CONFIG'
# ThakaaMed Docker Log Rotation
# Because infinite logs are like infinite browser tabs - eventually problematic

# Docker container logs
/var/log/thakaamed/docker/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 root root
    copytruncate
    sharedscripts
    postrotate
        # Gently nudge the collector to notice the rotation
        systemctl reload thakaamed-docker-collector 2>/dev/null || true
    endscript
}

# Application logs (keep longer for troubleshooting)
/var/log/thakaamed/application/*.log {
    daily
    missingok
    rotate 90
    compress
    delaycompress
    notifempty
    create 0640 root root
    copytruncate
}

# Security logs (keep much longer because security is important)
/var/log/thakaamed/security/*.log {
    daily
    missingok
    rotate 365
    compress
    delaycompress
    notifempty
    create 0640 root root
    copytruncate
}

# System logs
/var/log/thakaamed/system/*.log {
    daily
    missingok
    rotate 60
    compress
    delaycompress
    notifempty
    create 0640 root root
    copytruncate
}

# Medical logs (HIPAA compliance - keep for years)
/var/log/thakaamed/medical/*.log {
    daily
    missingok
    rotate 2555  # 7 years worth
    compress
    delaycompress
    notifempty
    create 0640 root root
    copytruncate
}

# Archive management - move old logs to archive directory
/var/log/thakaamed/*/*.log.365.gz {
    yearly
    maxage 2190  # 6 years
    compress
    compresscmd /usr/bin/xz
    compressext .xz
    compressoptions -9
    copytruncate
    postrotate
        # Move ancient logs to archive
        find /var/log/thakaamed -name "*.log.*.xz" -mtime +365 -exec mv {} /var/log/thakaamed/archive/ \; 2>/dev/null || true
        # Send notification that logs were archived
        logger "ThakaaMed: Archived old logs to /var/log/thakaamed/archive/"
    endscript
}
LOGROTATE_CONFIG

    success "Log rotation configured! Your logs will now age gracefully like fine wine! 🍷"
}

# ========================================================================
# HEALTH CHECK SCRIPT
# ========================================================================

create_health_check() {
    log "Creating health check script (because we need to check on the checker) 🩺"
    
    cat > /usr/local/bin/thakaamed-health-check.sh << 'HEALTH_SCRIPT'
#!/bin/bash
# ThakaaMed Health Check Script
# Like a doctor, but for logs

LOG_DIR="/var/log/thakaamed"
SERVICE_NAME="thakaamed-docker-collector"

check_service() {
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo "✅ Service is running"
        return 0
    else
        echo "❌ Service is not running"
        return 1
    fi
}

check_log_files() {
    local recent_logs=$(find "$LOG_DIR" -name "*.log" -mmin -10 | wc -l)
    if [[ $recent_logs -gt 0 ]]; then
        echo "✅ Log files are being updated ($recent_logs recent files)"
        return 0
    else
        echo "⚠️  No recent log updates"
        return 1
    fi
}

check_disk_space() {
    local usage=$(df "$LOG_DIR" | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $usage -lt 90 ]]; then
        echo "✅ Disk space OK (${usage}% used)"
        return 0
    else
        echo "⚠️  Disk space high (${usage}% used)"
        return 1
    fi
}

check_docker() {
    if systemctl is-active --quiet docker; then
        echo "✅ Docker is running"
        return 0
    else
        echo "❌ Docker is not running"
        return 1
    fi
}

main() {
    echo "🏥 ThakaaMed Health Check - $(date)"
    echo "============================================"
    
    local status=0
    
    check_service || status=1
    check_docker || status=1
    check_log_files || status=1
    check_disk_space || status=1
    
    if [[ $status -eq 0 ]]; then
        echo "🎉 All systems are GO!"
    else
        echo "🚨 Some issues detected!"
    fi
    
    return $status
}

main "$@"
HEALTH_SCRIPT

    chmod +x /usr/local/bin/thakaamed-health-check.sh
    
    success "Health check script created! Now you can check on your checker! 🩺"
}

# ========================================================================
# INSTALLATION VERIFICATION
# ========================================================================

verify_installation() {
    log "Running post-installation verification (trust but verify) ✅"
    
    # Check if Wazuh agent is still happy
    if systemctl is-active --quiet wazuh-agent; then
        success "✅ Wazuh agent is still running (we didn't break anything!)"
    else
        error "❌ Wazuh agent is not running (oops!)"
        return 1
    fi
    
    # Check if Docker is still happy
    if systemctl is-active --quiet docker; then
        success "✅ Docker is still running (containers are safe!)"
    else
        error "❌ Docker is not running (this is bad)"
        return 1
    fi
    
    # Check if our service starts
    systemctl daemon-reload
    systemctl enable thakaamed-docker-collector
    systemctl start thakaamed-docker-collector
    
    sleep 5  # Give it a moment to start
    
    if systemctl is-active --quiet thakaamed-docker-collector; then
        success "✅ ThakaaMed collector is running (we're live!)"
    else
        error "❌ ThakaaMed collector failed to start"
        return 1
    fi
    
    # Check if logs are being created
    sleep 10  # Give it time to create some logs
    
    if [[ -n "$(find "$LOG_DIR" -name "*.log" -mmin -2)" ]]; then
        success "✅ Logs are being created (the magic is working!)"
    else
        warning "⚠️  No logs created yet (might need more time)"
    fi
    
    success "🎊 Installation verification complete!"
}

# ========================================================================
# MAIN EXECUTION
# ========================================================================

main() {
    show_banner
    
    log "Starting ThakaaMed Docker Log Enhancement for existing Wazuh agent"
    log "Host: $(hostname) | Date: $(date) | User: $(whoami)"
    
    # Run all the steps
    check_prerequisites
    create_thakaamed_structure
    create_docker_collector
    create_systemd_service
    setup_log_rotation
    create_health_check
    verify_installation
    
    # Final status
    echo ""
    success "🎉 ENHANCEMENT COMPLETE! 🎉"
    echo ""
    info "📊 Current status:"
    info "   • Wazuh agent: $(systemctl is-active wazuh-agent)"
    info "   • Docker: $(systemctl is-active docker)"
    info "   • ThakaaMed collector: $(systemctl is-active thakaamed-docker-collector)"
    info "   • Running containers: $(docker ps --format '{{.Names}}' | wc -l)"
    echo ""
    info "📁 Log locations:"
    info "   • Docker logs: $LOG_DIR/docker/"
    info "   • Application logs: $LOG_DIR/application/"
    info "   • Security logs: $LOG_DIR/security/"
    info "   • System logs: $LOG_DIR/system/"
    echo ""
    info "🔧 Useful commands:"
    info "   • Check service: systemctl status thakaamed-docker-collector"
    info "   • View logs: tail -f $LOG_DIR/system/docker-collector.log"
    info "   • Health check: /usr/local/bin/thakaamed-health-check.sh"
    info "   • Emergency rollback: /usr/local/bin/rollback-docker-enhancement.sh"
    echo ""
    warning "⚠️  Note: If anything breaks, we blame Docker. Always Docker. 🐳"
    success "Happy monitoring! 🚀"
}

# ========================================================================
# SCRIPT ENTRY POINT
# ========================================================================

# Run the main function if this script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

# ========================================================================
# END OF SCRIPT
# ========================================================================
# If you made it this far, you deserve a cookie! 🍪
# Or at least a working Docker log monitoring system.
# We'll take either one, honestly.
# ======================================================================== 