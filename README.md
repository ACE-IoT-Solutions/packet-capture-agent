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
  "jwt": "your_api_key",
  "api_url": "https://app.visualbacnet.com/api/v2/upload",
  "gateway_name": "my-gateway",
  "client": "acme",
  "site": "headquarters",
  "analytics_enabled": true,
  "publish_to_volttron": true,
  "analytics_topic_prefix": null,
  "prometheus_enabled": true,
  "prometheus_metrics_path": "/var/lib/node_exporter/textfile_collector"
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
- `client`: Client identifier for organizing metrics (default: "client")
- `site`: Site identifier for organizing metrics (default: "site")
- `analytics_enabled`: Enable packet capture analytics processing (default: true)
- `publish_to_volttron`: Publish metrics to VOLTTRON message bus (default: true)
- `analytics_topic_prefix`: Prefix for analytics topics (default: /{client}/{site}/net-stats if not specified)
- `prometheus_enabled`: Enable writing metrics in Prometheus format for node_exporter (default: false)
- `prometheus_metrics_path`: Path where Prometheus metrics files will be written (default: /var/lib/node_exporter/textfile_collector)

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

## Analytics Features

The agent includes built-in analytics for BACnet packet captures. When `analytics_enabled` is set to true, the agent will process packet captures immediately after they are completed to extract network metrics. Analytics are run on the same schedule as packet captures.

### VOLTTRON Metrics

When `publish_to_volttron` is enabled, the agent will publish metrics to the VOLTTRON message bus. The metrics are published to topics using the format:

```
{analytics_topic_prefix}/{gateway_name}/{metric}
```

### Prometheus Metrics

When `prometheus_enabled` is enabled, the agent will write metrics in Prometheus text format to a file that can be consumed by the Prometheus Node Exporter's textfile collector. The agent uses the official prometheus_client library to ensure proper formatting and compatibility. The metrics are written to:

```
{prometheus_metrics_path}/bacnet_metrics.prom
```

This allows the metrics to be scraped by Prometheus and visualized in dashboards like Grafana. All metrics:
- Are prefixed with `bacnet_` for clear identification
- Include labels for `client`, `site`, and `gateway` for proper organization and filtering
- Use the same client and site IDs that are used in the VOLTTRON topic path
- Are stored as Prometheus Gauge type metrics suitable for values that can go up and down

### Published Metrics

- `score`: Overall network health score (0-100)
- `local_broadcast_ratio`: Percentage of local broadcast traffic
- `remote_station_ratio`: Percentage of unicast (point-to-point) traffic
- `whois_ratio`: Percentage of Who-Is/Who-Has discovery traffic
- `prop_acked_ratio`: Read Property response success rate
- `props_acked_ratio`: Read Property Multiple response success rate
- `packet_count`: Total number of packets analyzed
- `device_count`: Number of unique devices detected
- `message_types/{type}`: Count for each type of BACnet message
- `destination_types/{type}`: Count for each type of destination address

## Packet Processing Library

This agent originally used pyshark for packet processing, but has been refactored to use scapy. The change provides the following benefits:

- **Simplified dependencies**: Removes the need for nest_asyncio and avoids issues with asyncio event loop nesting
- **Better performance**: Scapy provides more efficient packet processing compared to pyshark
- **Less overhead**: Removes dependency on external tools like tshark
- **More direct access**: Works directly with packet data instead of going through parsing layers

## Version History
- 1.7.3:
  - properly close tcpdump processes on timeout
- 1.7.2: 
  - Properly handle errors making post request
  - Formatting changes
  - Retrieve upload URL from ace-agent.config
- 1.7.1: Fixed file name when uploading to API
- 1.7.0: Removed capture lock to enable simultaneous captures, added file cleanup, refactors, upload error handling bug
- 1.6.8: Assigned prometheus types appropriately
- 1.6.7: Improved error handling for config store updates and api key expiration
- 1.6.6: Added sigint for stopping timedout captures
- 1.6.5: Allowed setup with no interface specified
- 1.6.4: Fixed handling of periods with no packets captured
- 1.6.3: Updated default config
- 1.6.2: Fixed typo in health subsystem calls
- 1.6.1: Loads ace-agent.config for default configuration
- 1.6.0: Refactored to use scapy instead of pyshark for packet processing
- 1.5.0: Added client and site identifiers for better metrics organization and topic generation
- 1.4.1: Updated to use prometheus_client library for proper metrics formatting
- 1.4.0: Added Prometheus metrics support and made VOLTTRON publishing optional
- 1.3.2: Added helper method for publishing metrics
- 1.3.1: Integrated analytics directly into agent code
- 1.3.0: Added packet analytics processing and data bus publication
- 1.2.1: Added Config Store support
- 1.1.1: Added offline capture
- 1.0.0: Initial release