# 🚀 ThakaaMed Wazuh Package - Quick Install Guide

## For Existing Wazuh Agents (Recommended)

```bash
# 1. Download/copy this package to your server
# 2. Make scripts executable
chmod +x scripts/*.sh utils/*.sh

# 3. Run the enhancement script
sudo ./scripts/enhance-existing-agents-docker-logs.sh
```

## For Fresh Wazuh Installation

```bash
# 1. Set your Wazuh manager IP
export WAZUH_MANAGER_IP="your.manager.ip.here"

# 2. Run fresh installation
sudo ./scripts/deploy-fresh-wazuh-docker-agent.sh
```

## Emergency Rollback

```bash
sudo ./utils/rollback-docker-enhancement.sh
```

## Health Check

```bash
sudo ./utils/thakaamed-health-check.sh
```

For full documentation, see [README.md](README.md) 