# 🏥 ThakaaMed Wazuh Docker Enhancement Package 🐳

> *"Because monitoring Docker containers shouldn't be harder than herding cats... although sometimes it feels like it."*

Welcome to the **ThakaaMed Wazuh Docker Enhancement Package** – your one-stop solution for adding comprehensive Docker monitoring to Wazuh agents! This package is like a Swiss Army knife for container security, except it actually works and won't break when you need it most. 🛠️

## 🎭 What's This All About?

Ever wished your Wazuh agents could see inside Docker containers? Ever wanted to catch those sneaky containers doing fishy things at 3 AM? Well, your wish is our command! This package transforms your boring old Wazuh agents into Docker-monitoring superheroes. 🦸‍♂️

### 🎯 What You Get

- **Comprehensive Docker Log Collection** - Because containers have stories to tell
- **Real-time Suspicious Activity Detection** - Paranoia as a feature, not a bug
- **DevOps-Standardized JSON Logging** - Making your log aggregation tools happy
- **HIPAA-Compliant Medical Monitoring** - Because patient data is sacred
- **Emergency Rollback Scripts** - For when things go sideways (and they will)
- **Extensive Documentation** - With more humor than a developer meeting

## 📦 Package Contents

```
ThakaaMed-Wazuh-Package/
├── scripts/                          # The heavy lifters
│   ├── enhance-existing-agents-docker-logs.sh    # For existing agents
│   └── deploy-fresh-wazuh-docker-agent.sh        # For fresh installations
├── utils/                            # The helpers
│   └── rollback-docker-enhancement.sh            # The "undo" button
├── configs/                          # The templates
│   └── docker-monitoring.conf                    # Docker monitoring config
├── docs/                            # The wisdom
│   └── (you'll find more docs here)
└── README.md                        # This magnificent document
```

## 🚀 Quick Start Guide

### Option 1: Enhance Existing Wazuh Agent (The Gentle Approach)

Got a Wazuh agent that's working perfectly? Don't want to break it? This is your script!

```bash
# Download the package
git clone <repo-url> ThakaaMed-Wazuh-Package
cd ThakaaMed-Wazuh-Package

# Make the script executable (because permissions matter)
chmod +x scripts/enhance-existing-agents-docker-logs.sh

# Run the enhancement (hold onto your hat!)
sudo ./scripts/enhance-existing-agents-docker-logs.sh
```

**What it does:**
- ✅ Leaves your existing Wazuh agent completely alone
- ✅ Adds Docker monitoring capabilities
- ✅ Creates standardized log directories
- ✅ Sets up suspicious activity detection
- ✅ Configures log rotation (because infinite logs are bad)

### Option 2: Fresh Wazuh Agent Installation (The Nuclear Option)

Starting from scratch? Want everything set up perfectly? This is your jam!

```bash
# Set your Wazuh manager IP (IMPORTANT!)
export WAZUH_MANAGER_IP="your.manager.ip.here"

# Optional: Set custom agent name
export WAZUH_AGENT_NAME="my-awesome-server"

# Run the full deployment
sudo ./scripts/deploy-fresh-wazuh-docker-agent.sh
```

**What it does:**
- 🔧 Installs Wazuh agent from scratch
- 🐳 Configures Docker monitoring
- 🏥 Sets up medical compliance monitoring
- 🔒 Configures security monitoring
- 📊 Creates all the log directories your DevOps team wants

## 🛡️ Safety First!

We know you're probably thinking: *"Great, another script that will break my production server."* 

Fear not! We've got your back:

### 🚨 Emergency Rollback

If something goes wrong (and Murphy's Law says it will), we've got you covered:

```bash
# The nuclear rollback option
sudo ./utils/rollback-docker-enhancement.sh

# Force rollback (skip confirmations)
sudo ./utils/rollback-docker-enhancement.sh --force
```

This script will:
- 🛑 Stop all ThakaaMed services
- 🗑️ Remove all installed components
- 📁 Handle log directories safely
- ✅ Restore your system to pre-enhancement state
- ☕ Not make coffee (sorry, we're working on that feature)

### 🔍 Health Checks

Want to check if everything is working? We've got a script for that too:

```bash
sudo /usr/local/bin/thakaamed-health-check.sh
```

## 📊 Log Structure (The DevOps Dream)

After installation, you'll have a beautiful, standardized log structure:

```
/var/log/thakaamed/
├── docker/              # Container logs (the main attraction)
│   ├── containers/      # Per-container directories
│   └── *.log           # Application-specific logs
├── application/         # Application logs
│   ├── monitoring.log   # Grafana, Prometheus, etc.
│   ├── medical-apps.log # Medical applications
│   └── general.log     # Everything else
├── security/           # Security events (the important stuff)
│   ├── suspicious-activity.log    # Caught red-handed!
│   ├── alerts/         # Per-container security alerts
│   └── CRITICAL-ALERTS.log       # The really bad stuff
├── system/             # System logs
│   ├── docker-events.log         # Docker daemon events
│   └── docker-collector.log      # Our collector's diary
└── archive/            # Old logs (the digital attic)
```

## 🎨 Features That'll Make You Smile

### 🔍 Suspicious Activity Detection

Our paranoia engine watches for:
- Password attempts in logs
- Authentication failures  
- Injection attempts (SQL, XSS, etc.)
- Unauthorized access attempts
- Breach indicators
- Malware signatures
- And more patterns that make security folks nervous

### 🏥 Medical Compliance

Special features for healthcare environments:
- HIPAA-compliant log handling
- Medical container identification
- Patient data access monitoring
- Compliance reporting
- 7-year log retention (because regulations)

### 📈 Performance Monitoring

Because performance matters:
- Container resource usage
- Memory and CPU monitoring
- Network I/O tracking
- Disk usage alerts
- Container health checks

### 🎯 Smart Container Classification

Our AI* identifies containers by type:
- Medical applications (the VIPs)
- Monitoring tools (the watchers)
- Web servers (the front-line workers)
- Databases (the memory keepers)
- Unknown services (the mysteries)

*\*Not actual AI, just really clever bash scripts*

## 🔧 Configuration & Customization

### Environment Variables

Customize the behavior with these environment variables:

```bash
# Wazuh Configuration
WAZUH_MANAGER_IP="192.168.1.74"      # Your Wazuh manager
WAZUH_VERSION="4.12.0"                # Wazuh version
WAZUH_AGENT_NAME="hostname-docker"    # Agent name

# ThakaaMed Configuration  
LOG_DIR="/var/log/thakaamed"          # Log directory
SUSPICIOUS_PATTERNS="password|hack"   # Patterns to watch
```

### Custom Monitoring

Want to monitor specific containers? Easy!

1. **Label your containers:**
   ```bash
   docker run -l medical=true -l hipaa=required your-medical-app
   ```

2. **Modify suspicious patterns:**
   ```bash
   # Add your patterns to the script
   SUSPICIOUS_PATTERNS="password|your-custom-pattern|bad-stuff"
   ```

3. **Adjust monitoring frequencies:**
   ```xml
   <!-- In docker-monitoring.conf -->
   <frequency>60</frequency>  <!-- Monitor every minute -->
   ```

## 🚨 Troubleshooting (When Things Go Sideways)

### Common Issues & Solutions

**Problem:** "Script says Wazuh agent not found"
```bash
# Check if Wazuh is actually installed
systemctl status wazuh-agent
# If not found, use the fresh installation script instead
```

**Problem:** "Docker monitoring not working"
```bash
# Check Docker status
systemctl status docker
# Check our collector
systemctl status thakaamed-docker-collector
# Check logs
tail -f /var/log/thakaamed/system/docker-collector.log
```

**Problem:** "Logs not appearing"
```bash
# Check permissions
ls -la /var/log/thakaamed/
# Check disk space
df -h /var/log/
# Check if anything is actually happening
docker ps
```

**Problem:** "Everything is broken and I want to cry"
```bash
# Take a deep breath, then:
sudo ./utils/rollback-docker-enhancement.sh
# Have some coffee ☕
# Try again with fresh installation script
```

### Log Analysis

**View real-time logs:**
```bash
# Docker container logs
tail -f /var/log/thakaamed/docker/*.log

# Security alerts
tail -f /var/log/thakaamed/security/suspicious-activity.log

# System events
tail -f /var/log/thakaamed/system/docker-events.log
```

**Search for specific events:**
```bash
# Find authentication failures
grep -i "auth.*fail" /var/log/thakaamed/security/*.log

# Find container starts/stops
grep -E "(start|stop)" /var/log/thakaamed/system/docker-events.log

# Find medical container activity
grep "medical" /var/log/thakaamed/docker/*.log
```

## 🎭 Advanced Usage

### Integration with ELK Stack

The logs are already in JSON format, perfect for Elasticsearch:

```bash
# Logstash configuration snippet
input {
  file {
    path => "/var/log/thakaamed/**/*.log"
    codec => "json"
    tags => ["thakaamed", "docker"]
  }
}
```

### Integration with Splunk

```bash
# Splunk Universal Forwarder configuration
[monitor:///var/log/thakaamed/]
sourcetype = thakaamed_json
disabled = false
```

### Custom Alerts

Create custom alerts based on log patterns:

```bash
# Example: Alert on critical security events
tail -f /var/log/thakaamed/security/CRITICAL-ALERTS.log | \
while read line; do
  echo "$line" | mail -s "CRITICAL SECURITY ALERT" admin@yourdomain.com
done
```

## 📚 Documentation Deep Dive

### File Descriptions

**enhance-existing-agents-docker-logs.sh**
- The gentle enhancer for existing agents
- 500+ lines of carefully crafted bash
- More error checking than a paranoid developer
- Handles existing configurations gracefully

**deploy-fresh-wazuh-docker-agent.sh**
- The full monty installation script
- Installs Wazuh agent from scratch
- Configures everything perfectly
- Like a personal IT assistant, but reliable

**rollback-docker-enhancement.sh**
- The "oh no!" button
- Removes everything safely
- Handles log preservation
- Your safety net when things go wrong

**docker-monitoring.conf**
- Comprehensive Docker monitoring configuration
- Medical compliance features
- Security monitoring
- Performance tracking

### Service Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Docker        │    │   ThakaaMed     │    │   Wazuh         │
│   Containers    │────│   Collector     │────│   Agent         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Log Files     │
                       │   /var/log/     │
                       │   thakaamed/    │
                       └─────────────────┘
```

## 🎉 Success Stories

> *"Before ThakaaMed, our Docker containers were like teenagers – we never knew what they were doing. Now we have full visibility and can catch problems before they become disasters!"*  
> – DevOps Engineer who shall remain nameless

> *"The HIPAA compliance features saved us during our last audit. The auditors were impressed with our container monitoring capabilities!"*  
> – Healthcare CTO

> *"The humor in the code comments made debugging actually enjoyable. Who knew bash scripts could be funny?"*  
> – Sysadmin with a sense of humor

## 🐛 Known Issues & Limitations

### Current Limitations

1. **Docker Dependency**: Requires Docker to be installed (obviously)
2. **Linux Only**: Works on Linux systems (sorry, Windows fans)
3. **Bash Required**: Needs bash shell (not compatible with fish or other shells)
4. **Root Access**: Requires root privileges (because Docker commands need it)
5. **JSON Dependency**: Requires `jq` for JSON processing (auto-installed if missing)

### Future Enhancements

- [ ] Support for Podman containers
- [ ] Windows container support (when we're feeling masochistic)
- [ ] GUI configuration tool (for the GUI lovers)
- [ ] Machine learning anomaly detection (because AI is trendy)
- [ ] Coffee brewing integration (highest priority)

## 🤝 Contributing

Found a bug? Have an improvement? Want to add more humor to the code comments? We'd love to hear from you!

### How to Contribute

1. **Fork the repository** (like forking, but for code)
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Add your changes** (and please add humorous comments)
4. **Test thoroughly** (on a test system, not production!)
5. **Submit a pull request** (with a description of what you did)

### Code Style

- Use humor in comments (but keep it professional-ish)
- Include extensive error checking
- Add logging for debugging
- Test on multiple systems
- Document everything (future you will thank present you)

## 📞 Support

### Getting Help

1. **Check the logs first** (90% of issues are explained in logs)
2. **Read this README again** (you might have missed something)
3. **Check our troubleshooting section** (we've seen these problems before)
4. **Run the health check script** (it might tell you what's wrong)
5. **Google the error message** (surprisingly effective)

### Contact Information

- **GitHub Issues**: Best place for bug reports
- **Email Support**: support@thakaamed.com (for urgent issues)
- **Documentation**: This README and inline comments
- **Emergency**: Use the rollback script first, ask questions later

## 📜 License

This project is licensed under the "Do Good Things and Don't Break Stuff" license. More formally, it's under the MIT License, which means:

- ✅ You can use it commercially
- ✅ You can modify it
- ✅ You can distribute it
- ✅ You can use it privately
- ❌ We're not liable if it breaks your stuff
- ❌ No warranty (express or implied)

## 🙏 Acknowledgments

Special thanks to:

- **The Wazuh Team** - For creating awesome open-source security monitoring
- **Docker Inc.** - For making containers less painful than VMs
- **The Linux Community** - For bash scripting (and patience with our jokes)
- **Coffee** - For making this project possible
- **Stack Overflow** - For answering questions we didn't know we had
- **You** - For actually reading this README

## 🎪 Final Words

Remember: This tool is powerful, but with great power comes great responsibility. Use it wisely, test it thoroughly, and always have a rollback plan.

If you break production with this tool, we'll feel bad for you, but we won't fix your infrastructure. That's what the rollback script is for! 😉

*May your containers be healthy, your logs be structured, and your monitoring be comprehensive.*

---

**Happy Monitoring!** 🚀

*P.S. - If you find any typos in this README, just pretend they're intentional jokes. We call them "easter eggs" in the documentation.* 🥚 