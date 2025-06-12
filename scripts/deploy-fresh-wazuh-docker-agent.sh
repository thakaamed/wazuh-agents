#!/bin/bash
# ========================================================================
# ThakaaMed Fresh Wazuh Agent Deployment with Docker Integration
# ========================================================================
# 
# 🚀 What this script does:
# - Installs a brand new Wazuh agent from scratch
# - Configures it to talk to your Wazuh manager
# - Adds comprehensive Docker log monitoring
# - Sets up all the ThakaaMed standardized logging
# - Makes your security team happy (or at least less grumpy)
#
# 🎯 When to use this script:
# - Fresh server installations
# - Servers without existing Wazuh agents
# - When you want to start from a clean slate
# - When the existing agent is so broken it's easier to start over
#
# 🚨 When NOT to use this script:
# - Servers with existing Wazuh agents (use enhance-existing-agents instead)
# - Production servers during business hours (unless you like stress)
# - When you've had too much coffee (wait for the jitters to stop)
#
# ========================================================================

set -euo pipefail

# ========================================================================
# CONFIGURATION SECTION
# ========================================================================
# Modify these values for your environment

# Wazuh Manager Configuration
WAZUH_MANAGER_IP="${WAZUH_MANAGER_IP:-192.168.1.74}"  # Change this!
WAZUH_VERSION="${WAZUH_VERSION:-4.12.0}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-$(hostname)-docker}"

# ThakaaMed Configuration
LOG_DIR="/var/log/thakaamed"
SUSPICIOUS_PATTERNS="password|login|auth|fail|error|unauthorized|denied|attack|hack|exploit|injection|xss|traversal|breach|malware|suspicious|anomaly"

# Colors for beautiful output 🎨
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

show_banner() {
    echo -e "${PURPLE}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║        🏥 ThakaaMed Fresh Wazuh Agent Deployment 🐳          ║"
    echo "║                                                              ║"
    echo "║     From zero to hero: Complete Wazuh + Docker monitoring   ║"
    echo "║                                                              ║"
    echo "║  Warning: May cause sudden increases in security posture!   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ========================================================================
# PREREQUISITE CHECKS
# ========================================================================

check_prerequisites() {
    log "🔍 Checking prerequisites (making sure we can actually do this)"
    
    # Root check
    if [[ $EUID -ne 0 ]]; then
        error "This script needs root privileges"
        error "Please run: sudo $0"
        exit 1
    fi
    
    # Check if Wazuh agent already exists
    if systemctl list-units --full -all | grep -Fq "wazuh-agent.service"; then
        error "Wazuh agent already exists on this system!"
        error "Use the 'enhance-existing-agents-docker-logs.sh' script instead"
        error "Or remove the existing agent first if you want a fresh install"
        exit 1
    fi
    
    # Check OS compatibility
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot determine OS version"
        exit 1
    fi
    
    source /etc/os-release
    case "$ID" in
        ubuntu|debian)
            success "✅ OS compatibility: $PRETTY_NAME"
            ;;
        *)
            warning "⚠️  Untested OS: $PRETTY_NAME"
            warning "This script is designed for Ubuntu/Debian"
            read -p "Continue anyway? (y/N): " confirm
            [[ ! "$confirm" =~ ^[Yy]$ ]] && exit 1
            ;;
    esac
    
    # Check internet connectivity
    if ! ping -c 1 packages.wazuh.com &> /dev/null; then
        error "Cannot reach Wazuh package repository"
        error "Check your internet connection"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        warning "⚠️  Docker not found. Docker monitoring will be limited."
        warning "Install Docker first for full functionality"
    else
        success "✅ Docker found: $(docker --version)"
    fi
    
    # Validate Wazuh manager IP
    if [[ "$WAZUH_MANAGER_IP" == "192.168.1.74" ]]; then
        warning "⚠️  Using default Wazuh manager IP: $WAZUH_MANAGER_IP"
        warning "Make sure this is correct!"
        read -p "Continue with this IP? (y/N): " confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && exit 1
    fi
    
    success "🎯 All prerequisites check out!"
}

# ========================================================================
# WAZUH AGENT INSTALLATION
# ========================================================================

install_wazuh_repository() {
    log "📦 Adding Wazuh repository (getting the good stuff)"
    
    # Install required packages
    apt-get update -qq
    apt-get install -y curl gnupg lsb-release apt-transport-https
    
    # Add Wazuh GPG key
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
    
    # Add repository
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
    
    # Update package list
    apt-get update -qq
    
    success "✅ Wazuh repository added successfully"
}

install_wazuh_agent() {
    log "🔧 Installing Wazuh agent (the main event)"
    
    # Set environment variables for automatic configuration
    export WAZUH_MANAGER="$WAZUH_MANAGER_IP"
    export WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME"
    
    # Install the agent
    apt-get install -y wazuh-agent=$WAZUH_VERSION-1
    
    # Verify installation
    if [[ ! -f /var/ossec/bin/wazuh-control ]]; then
        error "Wazuh agent installation failed"
        exit 1
    fi
    
    success "✅ Wazuh agent $WAZUH_VERSION installed"
}

configure_wazuh_agent() {
    log "⚙️  Configuring Wazuh agent (making it smart)"
    
    # Backup original configuration
    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup
    
    # Create custom configuration directory
    mkdir -p /var/ossec/etc/ossec.conf.d
    
    # Basic agent configuration
    cat > /var/ossec/etc/ossec.conf.d/basic-config.conf << EOF
<!-- Basic ThakaaMed Agent Configuration -->
<ossec_config>
  <!-- Enable log analysis -->
  <global>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.0.0.0/8</white_list>
    <white_list>172.16.0.0/12</white_list>
    <white_list>192.168.0.0/16</white_list>
  </global>

  <!-- System monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>7200</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore>no</auto_ignore>
    <alert_new_files>yes</alert_new_files>
    
    <!-- Monitor important directories -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>
    
    <!-- Ignore noisy directories -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
  </syscheck>

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
  </active-response>
</ossec_config>
EOF

    success "✅ Basic agent configuration created"
}

# ========================================================================
# DOCKER INTEGRATION
# ========================================================================

configure_docker_monitoring() {
    log "🐳 Configuring Docker monitoring (the fun part)"
    
    if ! command -v docker &> /dev/null; then
        warning "⚠️  Docker not installed, skipping Docker configuration"
        return 0
    fi
    
    # Docker log collection configuration
    cat > /var/ossec/etc/ossec.conf.d/docker-monitoring.conf << 'EOF'
<!-- ThakaaMed Docker Monitoring Configuration -->
<ossec_config>
  <!-- Docker container logs via JSON driver -->
  <localfile>
    <log_format>docker</log_format>
    <location>/var/lib/docker/containers/*/*-json.log</location>
  </localfile>
  
  <!-- Docker daemon logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/docker.log</location>
  </localfile>
  
  <!-- Docker systemd service logs -->
  <localfile>
    <log_format>command</log_format>
    <command>journalctl -u docker.service -f --since "1 minute ago" --output json</command>
    <frequency>60</frequency>
  </localfile>

  <!-- Docker events monitoring -->
  <localfile>
    <log_format>command</log_format>
    <command>timeout 30 docker events --format '{"time":"{{.Time}}","action":"{{.Action}}","type":"{{.Type}}","actor":{{json .Actor}}}' --since 30s 2>/dev/null || echo '{"error":"docker_events_timeout"}'</command>
    <frequency>60</frequency>
  </localfile>
  
  <!-- Container health monitoring -->
  <localfile>
    <log_format>command</log_format>
    <command>docker ps --format '{"container":"{{.Names}}","status":"{{.Status}}","image":"{{.Image}}","created":"{{.CreatedAt}}","ports":"{{.Ports}}"}' 2>/dev/null | jq -s '{"containers":.,"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}'</command>
    <frequency>300</frequency>
  </localfile>
</ossec_config>
EOF

    success "✅ Docker monitoring configuration created"
}

# ========================================================================
# THAKAAMED LOG INFRASTRUCTURE
# ========================================================================

setup_thakaamed_infrastructure() {
    log "🏗️  Setting up ThakaaMed log infrastructure (building the foundation)"
    
    # Create directory structure
    mkdir -p "$LOG_DIR"/{docker,application,security,api,medical,system,archive}
    mkdir -p "$LOG_DIR/docker/containers"
    mkdir -p "$LOG_DIR/application/"{web,api,background}
    mkdir -p "$LOG_DIR/security/"{alerts,violations,suspicious}
    mkdir -p "$LOG_DIR/system/"{events,performance,errors}
    
    # Set permissions
    chown -R root:root "$LOG_DIR"
    chmod -R 755 "$LOG_DIR"
    
    # Copy the Docker collector script from our enhancement
    if [[ -f "/tmp/thakaamed-docker-collector.sh" ]]; then
        cp /tmp/thakaamed-docker-collector.sh /usr/local/bin/
        chmod +x /usr/local/bin/thakaamed-docker-collector.sh
    else
        # Create a basic version if the enhanced one isn't available
        create_basic_docker_collector
    fi
    
    success "✅ ThakaaMed infrastructure created"
}

create_basic_docker_collector() {
    log "📝 Creating basic Docker collector (fallback version)"
    
    cat > /usr/local/bin/thakaamed-docker-collector.sh << 'BASIC_COLLECTOR'
#!/bin/bash
# Basic ThakaaMed Docker Collector
# This is a simplified version for fresh installations

LOG_DIR="/var/log/thakaamed"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/system/docker-collector.log"
}

main() {
    log "ThakaaMed Basic Docker Collector starting"
    
    # Simple container log collection
    while true; do
        docker ps --format '{{.Names}}' 2>/dev/null | while read -r container; do
            [[ -z "$container" ]] && continue
            
            # Create log file for container
            local log_file="$LOG_DIR/docker/${container}.log"
            
            # Collect recent logs
            docker logs --timestamps --tail=10 "$container" 2>&1 | while read -r line; do
                echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"container\":\"$container\",\"message\":\"$line\"}" >> "$log_file"
            done
        done
        
        sleep 60
    done
}

mkdir -p "$LOG_DIR"/{docker,system}
main "$@"
BASIC_COLLECTOR

    chmod +x /usr/local/bin/thakaamed-docker-collector.sh
    
    success "✅ Basic Docker collector created"
}

# ========================================================================
# SERVICE CONFIGURATION
# ========================================================================

setup_services() {
    log "⚙️  Setting up services (making it all work together)"
    
    # Create systemd service for Docker collector
    cat > /etc/systemd/system/thakaamed-docker-collector.service << 'SERVICE_FILE'
[Unit]
Description=ThakaaMed Docker Log Collector
After=docker.service wazuh-agent.service
Requires=docker.service
Wants=wazuh-agent.service

[Service]
Type=simple
ExecStart=/usr/local/bin/thakaamed-docker-collector.sh
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=thakaamed-docker-collector
User=root
Group=root

[Install]
WantedBy=multi-user.target
SERVICE_FILE

    # Set up log rotation
    cat > /etc/logrotate.d/thakaamed-docker << 'LOGROTATE_CONFIG'
/var/log/thakaamed/docker/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 root root
    copytruncate
}

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
LOGROTATE_CONFIG

    # Enable services
    systemctl daemon-reload
    systemctl enable thakaamed-docker-collector
    
    success "✅ Services configured"
}

# ========================================================================
# FIREWALL CONFIGURATION
# ========================================================================

configure_firewall() {
    log "🔥 Configuring firewall (opening the necessary doors)"
    
    # Allow Wazuh agent communication
    if command -v ufw &> /dev/null; then
        log "   Configuring UFW firewall..."
        ufw allow out 1514/tcp comment "Wazuh agent"
        ufw allow out 1515/tcp comment "Wazuh enrollment"
        success "   ✅ UFW rules added"
    elif command -v firewall-cmd &> /dev/null; then
        log "   Configuring firewalld..."
        firewall-cmd --permanent --add-port=1514/tcp
        firewall-cmd --permanent --add-port=1515/tcp
        firewall-cmd --reload
        success "   ✅ Firewalld rules added"
    else
        warning "   ⚠️  No recognized firewall found"
        warning "   Make sure ports 1514 and 1515 are open for Wazuh communication"
    fi
    
    success "🎯 Firewall configuration complete"
}

# ========================================================================
# SERVICE STARTUP
# ========================================================================

start_services() {
    log "🚀 Starting services (the moment of truth)"
    
    # Start Wazuh agent
    log "   Starting Wazuh agent..."
    systemctl restart wazuh-agent
    sleep 5
    
    if systemctl is-active --quiet wazuh-agent; then
        success "   ✅ Wazuh agent is running"
    else
        error "   ❌ Wazuh agent failed to start"
        error "   Check logs: journalctl -u wazuh-agent"
        return 1
    fi
    
    # Start Docker collector (if Docker is available)
    if command -v docker &> /dev/null && systemctl is-active --quiet docker; then
        log "   Starting ThakaaMed Docker collector..."
        systemctl start thakaamed-docker-collector
        sleep 3
        
        if systemctl is-active --quiet thakaamed-docker-collector; then
            success "   ✅ ThakaaMed Docker collector is running"
        else
            warning "   ⚠️  ThakaaMed Docker collector failed to start"
            warning "   This is not critical - check logs later"
        fi
    else
        info "   ℹ️  Docker not available - skipping Docker collector"
    fi
    
    success "🎯 Services started successfully"
}

# ========================================================================
# VERIFICATION
# ========================================================================

verify_installation() {
    log "✅ Verifying installation (checking our work)"
    
    local issues=0
    
    # Check Wazuh agent status
    if systemctl is-active --quiet wazuh-agent; then
        success "   ✅ Wazuh agent: Running"
    else
        error "   ❌ Wazuh agent: Not running"
        issues=$((issues + 1))
    fi
    
    # Check agent connectivity (basic check)
    if /var/ossec/bin/wazuh-control status | grep -q "wazuh-agentd is running"; then
        success "   ✅ Wazuh processes: Running"
    else
        warning "   ⚠️  Some Wazuh processes may not be running"
        issues=$((issues + 1))
    fi
    
    # Check log directories
    if [[ -d "$LOG_DIR" ]]; then
        success "   ✅ ThakaaMed directories: Created"
    else
        error "   ❌ ThakaaMed directories: Missing"
        issues=$((issues + 1))
    fi
    
    # Check Docker collector (if applicable)
    if command -v docker &> /dev/null; then
        if systemctl is-active --quiet thakaamed-docker-collector; then
            success "   ✅ Docker collector: Running"
        else
            warning "   ⚠️  Docker collector: Not running"
        fi
    fi
    
    if [[ $issues -eq 0 ]]; then
        success "🎉 All verification checks passed!"
        return 0
    else
        warning "⚠️  $issues issues found - check logs for details"
        return 1
    fi
}

# ========================================================================
# FINAL REPORT
# ========================================================================

show_final_report() {
    echo ""
    success "🎊 DEPLOYMENT COMPLETE! 🎊"
    echo ""
    info "📊 Installation Summary:"
    info "   • Wazuh Agent: $WAZUH_VERSION"
    info "   • Manager IP: $WAZUH_MANAGER_IP"
    info "   • Agent Name: $WAZUH_AGENT_NAME"
    info "   • ThakaaMed Integration: Enabled"
    
    if command -v docker &> /dev/null; then
        info "   • Docker Monitoring: Enabled"
        local container_count=$(docker ps --format '{{.Names}}' 2>/dev/null | wc -l || echo "0")
        info "   • Monitored Containers: $container_count"
    else
        info "   • Docker Monitoring: Disabled (Docker not installed)"
    fi
    
    echo ""
    info "📁 Log Locations:"
    info "   • Wazuh logs: /var/ossec/logs/"
    info "   • ThakaaMed logs: $LOG_DIR/"
    info "   • Docker logs: $LOG_DIR/docker/"
    info "   • Security logs: $LOG_DIR/security/"
    
    echo ""
    info "🔧 Useful Commands:"
    info "   • Agent status: systemctl status wazuh-agent"
    info "   • Docker collector: systemctl status thakaamed-docker-collector"
    info "   • View agent logs: tail -f /var/ossec/logs/ossec.log"
    info "   • View Docker logs: tail -f $LOG_DIR/docker/*.log"
    
    echo ""
    info "🔍 Next Steps:"
    info "   1. Check Wazuh manager dashboard for this agent"
    info "   2. Verify log collection is working"
    info "   3. Configure additional monitoring as needed"
    info "   4. Test alert generation"
    
    echo ""
    warning "⚠️  Important Notes:"
    warning "   • Agent needs to be approved on Wazuh manager"
    warning "   • Firewall rules may need adjustment"
    warning "   • Monitor disk space for log files"
    
    echo ""
    success "🚀 Your server is now protected by Wazuh with Docker monitoring!"
    success "Welcome to the ThakaaMed security family! 🏥"
}

# ========================================================================
# MAIN EXECUTION
# ========================================================================

main() {
    show_banner
    
    log "🚀 Starting fresh Wazuh agent deployment with Docker integration"
    log "Host: $(hostname) | Date: $(date) | User: $(whoami)"
    
    # Run all deployment steps
    check_prerequisites
    install_wazuh_repository
    install_wazuh_agent
    configure_wazuh_agent
    configure_docker_monitoring
    setup_thakaamed_infrastructure
    setup_services
    configure_firewall
    start_services
    
    # Verify and report
    if verify_installation; then
        show_final_report
    else
        error "⚠️  Deployment completed with some issues"
        error "Check the logs and fix any problems before proceeding"
        exit 1
    fi
}

# ========================================================================
# SCRIPT ENTRY POINT
# ========================================================================

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "ThakaaMed Fresh Wazuh Agent Deployment Script"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Environment Variables:"
        echo "  WAZUH_MANAGER_IP    IP address of Wazuh manager (default: 192.168.1.74)"
        echo "  WAZUH_VERSION       Wazuh version to install (default: 4.12.0)"
        echo "  WAZUH_AGENT_NAME    Agent name (default: hostname-docker)"
        echo ""
        echo "Examples:"
        echo "  sudo $0"
        echo "  sudo WAZUH_MANAGER_IP=10.0.0.100 $0"
        echo "  sudo WAZUH_AGENT_NAME=web-server-01 $0"
        exit 0
        ;;
    "")
        # No arguments - run main function
        main "$@"
        ;;
    *)
        error "Unknown option: $1"
        error "Use --help for usage information"
        exit 1
        ;;
esac

# ========================================================================
# END OF SCRIPT
# ========================================================================
# Congratulations! You've successfully deployed a Wazuh agent with
# Docker monitoring. Your security posture just got a major upgrade! 🚀
# 
# Remember: With great monitoring comes great responsibility.
# Use this power wisely! 🕷️
# ======================================================================== 