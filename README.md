# Packet Capture Agent

A VOLTTRON agent that captures network packets on a configurable protocol and port list and optionally uploads them to an API.

## Configuration

This agent uses the VOLTTRON config store for configuration. You can add or update the configuration with:

```
vctl config store <agent_vip_identity> config <path_to_config_file> --json
```

### Example Configuration

```json
{
  "capture_duration": 300,
  "capture_interval": 3600,
  "upload_interval": 60,
  "interface": "eth0",
  "capture_path": "/var/lib/volttron/packet_captures",
  "protocol": "UDP",
  "ports": [47808, 47809],
  "api_key": "your_api_key",
  "api_url": "https://app.visualbacnet.com/api/v2/upload",
  "gateway_name": "my-gateway"
}
```

### Configuration Options

- `capture_duration`: Duration of each packet capture in seconds (default: 300)
- `capture_interval`: Interval between captures in seconds (default: 3600)
- `upload_interval`: Interval for checking and uploading captures in seconds (default: 60)
- `interface`: Network interface to capture on (optional)
- `capture_path`: Path to store capture files (default: /var/lib/volttron/packet_captures)
- `protocol`: Protocol to capture (default: UDP)
- `ports`: List of ports or single port to capture (default: 47808)
- `api_key`: API key for upload service
- `api_url`: URL for upload service (default: https://app.visualbacnet.com/api/v2/upload)
- `gateway_name`: Name of the gateway (default: system hostname)

## Installation

1. Clone the repository
2. Install the agent

```
vctl install <agent_dir> --agent-config <config_file> --start
```

3. Configure the agent using the config store (optional, if you want to update the config)

```
vctl config store <agent_vip_identity> config <path_to_config_file> --json
```

## Version History
1.2.1: Added Config Store support
1.1.1: Added offline capture
1.0.0: Initial release