"""
Cristian Romo
cristian@aceiotsolutions.com
Andrew Rodgers
andrew@aceiotsolutions.com

Capture network packets on a configurable protocol and port list
Enable upload of packet captures to a given API
Process packet captures to extract network performance metrics and statistics
Publish analytics results to VOLTTRON message bus

"""
 # pylint: disable=C0413

__docformat__ = "reStructuredText"

import glob
import gzip
import logging
import os
import signal
import sys
import traceback
from datetime import datetime, timedelta, timezone
from typing import Dict, Type, Union

import gevent
import grequests
from opentelemetry import metrics as otel_metrics
from opentelemetry.metrics import Observation
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
import volttron.platform.jsonapi as json
from gevent import subprocess
from volttron.platform.agent import utils
from volttron.platform.messaging.health import STATUS_BAD, STATUS_GOOD
from volttron.platform.vip.agent import Agent, Core

utils.setup_logging()
_log = logging.getLogger(__name__)
_log.info("setup logging")
# Import local analytics module
from packet_capture.analytics import (
    generate_scores,
    get_local_broadcast,
    process_pcap,
)

__version__ = "1.9.0"


def packet_capture(config_path, **kwargs):
    """
    Parses the Agent configuration and returns an instance of
    the agent created using that configuration.

    :param config_path: Path to a configuration file.
    :type config_path: str
    :returns: PacketCapture
    :rtype: PacketCapture
    """
    # We'll use config file only if explicitly provided, otherwise defaults
    # will be used and config store will provide actual configuration
    try:
        config = utils.load_config(config_path)
    except Exception:
        config = {}
    _log.debug("returning agent with default config")

    return PacketCapture(config, **kwargs)


class PacketCapture(Agent):
    """
    Document agent constructor here.
    """

    def __init__(self, config, **kwargs):
        super(PacketCapture, self).__init__(**kwargs)
        self.default_config = {
            "capture_duration": 300,
            "capture_interval": 60 * 60,
            "upload_interval": 60,
            "interface": None,
            "capture_path": "/var/lib/volttron/packet_captures",
            "protocol": "UDP",
            "ports": 47808,
            "jwt": None,
            "api_url": None,
            "gateway_name": os.uname()[1],  # Default to the hostname
            "gateway": None,
            "client": "client",  # Default client ID
            "site": "site",  # Default site ID
            "analytics_enabled": True,
            "publish_to_volttron": False,
            "analytics_topic_prefix": None,  # Will be auto-generated if None
        }
        self.ace_agent_config = self.get_default_config_from_agent_file()
        self.default_config.update(self.ace_agent_config)

        # Initialize with default values if no config provided, will be updated by configure method
        self.capture_duration = config.get(
            "capture_duration", self.default_config["capture_duration"]
        )
        self.capture_interval = config.get(
            "capture_interval", self.default_config["capture_interval"]
        )
        self.upload_interval = config.get(
            "upload_interval", self.default_config["upload_interval"]
        )
        self.interface = config.get("interface", self.default_config["interface"])
        self.capture_path = config.get(
            "capture_path", self.default_config["capture_path"]
        )
        self.protocol = config.get("protocol", self.default_config["protocol"])
        self.ports = config.get("ports", self.default_config["ports"])
        self.api_key = config.get("jwt", self.default_config["jwt"])
        self.api_url = config.get("api_url", self.default_config["api_url"])
        self.gateway_name = self.ace_agent_config.get(
            "gateway", self.default_config["gateway_name"]
        ).replace("_", "-")
        self.gateway_slug = config.get("gateway", self.default_config["gateway"])
        self.client = config.get("client", self.default_config["client"])
        self.site = config.get("site", self.default_config["site"])
        self.analytics_enabled = config.get(
            "analytics_enabled", self.default_config["analytics_enabled"]
        )
        self.publish_to_volttron = config.get(
            "publish_to_volttron", self.default_config["publish_to_volttron"]
        )
        # Generate analytics topic prefix if not provided
        config_topic_prefix = config.get("analytics_topic_prefix")
        if config_topic_prefix:
            self.analytics_topic_prefix = config_topic_prefix
        else:
            self.analytics_topic_prefix = f"/{self.client}/{self.site}/net-stats"
        self.gateway = config.get("gateway")

        # Cache for broadcast addresses
        self.broadcast_addrs = None

        self._meter_provider = None
        self._meter = None
        self._otlp_metrics = {}
        self._metric_store: Dict[str, tuple] = {}

        self.captures: Dict[str, any] = {}
        self.upload_lock = gevent.lock.BoundedSemaphore()
        self.analytics_lock = gevent.lock.BoundedSemaphore()
        self.data_path = kwargs.get("data_path", None)

        # Store task references for reconfiguration
        self.capture_task = None
        self.upload_task = None
        self.current_capture = None
        self.vip.config.set_default("config", self.default_config)
        self.vip.config.subscribe(
            self.configure, actions=["NEW", "UPDATE"], pattern="config"
        )
        _log.info("completed agent class init")

    def configure(self, config_name, action, contents):
        """
        Called after the Agent has connected to the message bus.
        If a configuration exists at startup this will be called before onstart.

        Is called every time the configuration in the store changes.
        """
        _log.info(f"Configuring agent with {config_name}")

        if action == "NEW" or action == "UPDATE":
            try:
                _log.debug(contents)
                config = contents

                # Update agent parameters with new config
                self.capture_duration = config.get(
                    "capture_duration", self.default_config["capture_duration"]
                )
                self.capture_interval = config.get(
                    "capture_interval", self.default_config["capture_interval"]
                )
                self.upload_interval = config.get(
                    "upload_interval", self.default_config["upload_interval"]
                )
                self.interface = config.get(
                    "interface", self.default_config["interface"]
                )
                self.capture_path = config.get(
                    "capture_path", self.default_config["capture_path"]
                )
                self.protocol = config.get("protocol", self.default_config["protocol"])
                self.ports = config.get("ports", self.default_config["ports"])
                self.api_key = config.get("jwt", self.default_config["jwt"])
                self.gateway = config.get("gateway", self.default_config["gateway"])
                self.gateway_name = self.ace_agent_config.get(
                    "gateway", self.default_config["gateway_name"]
                ).replace("_", "-")
                self.client = config.get("client", self.default_config["client"])
                self.site = config.get("site", self.default_config["site"])
                self.analytics_enabled = config.get(
                    "analytics_enabled", self.default_config["analytics_enabled"]
                )
                self.publish_to_volttron = config.get(
                    "publish_to_volttron", self.default_config["publish_to_volttron"]
                )
                # Generate analytics topic prefix if not provided
                config_topic_prefix = config.get("analytics_topic_prefix")
                if config_topic_prefix:
                    self.analytics_topic_prefix = config_topic_prefix
                else:
                    self.analytics_topic_prefix = (
                        f"/{self.client}/{self.site}/net-stats"
                    )

                _log.info(
                    f"Updated configuration: capture_interval={self.capture_interval}, "
                    f"capture_duration={self.capture_duration}, protocol={self.protocol}, "
                    f"ports={self.ports}, analytics_enabled={self.analytics_enabled}, "
                    f"client={self.client}, site={self.site}, "
                    f"publish_to_volttron={self.publish_to_volttron}"
                )
                if not self.interface:
                    _log.info(
                        "No interface specified in configuration."
                        " listening on all interfaces this may not be desired"
                    )
                if not self.api_key:
                    _log.error("API key not set. Skipping configuration update.")
                    self.vip.health.set_status(
                        STATUS_BAD, "API key, API URL or interface not set."
                    )
                # Log analytics status
                if self.analytics_enabled:
                    _log.info(
                        "Analytics processing enabled, will run after each packet capture"
                    )
                    if self.publish_to_volttron:
                        _log.info(
                            "Publishing metrics to VOLTTRON message bus with prefix: "
                            f"{self.analytics_topic_prefix}"
                        )
                    _log.info(
                        f"Pushing OTLP metrics to http://localhost:4318/v1/metrics"
                        f" with labels client={self.client}, site={self.site}, gateway={self.gateway_name}"
                    )

            except Exception as e:
                _log.error(f"could not configure: {e}")
            # Initialize data path if needed
            self.initialize_data_path(self.get_agent_data_path())

            # Restart periodic tasks with new configuration if agent is already started
            self._restart_periodic_tasks()
            sys.stdout.flush()
            sys.stderr.flush()
            gevent.sleep(1)

    def get_default_config_from_agent_file(self):
        """
        Returns the default configuration for the agent.
        This is used to set the default values for the agent's parameters.
        """
        try:
            with open(
                os.path.join("/var/lib/volttron", "ace-agent.config"),
                "r",
                encoding="utf-8",
            ) as f:
                _log.info("Reading default ace-agent config file")
                return json.load(f)
        except Exception as e:
            _log.error(f"Error reading default ace-agent config file: {e}")
            return {}

    def get_agent_data_path(self) -> str:
        """
        Returns the path to the agent's data directory.
        This is where the agent can store its state.
        """
        # Assuming the default path for Volttron's data directory
        # You can customize this if your agent has a different data path.
        if self.capture_path is not None:
            return self.capture_path
        data_path = os.path.join(
            os.getcwd(), os.path.basename(os.getcwd()) + ".agent-data"
        )
        if os.path.exists(data_path):
            return data_path
        return os.getcwd()

    def initialize_data_path(self, capture_path: str) -> None:
        """
        Initialize the data path for the agent.
        Create the directory if it does not exist.
        :param capture_path: The path to the capture directory.
        """
        if not os.path.exists(capture_path):
            os.makedirs(capture_path)
            _log.info(f"Created capture directory: {capture_path}")
        else:
            _log.info(f"Using existing capture directory: {capture_path}")

    def publish_metric(self, metric_name: str, value: Union[float, int, str]) -> None:
        """
        Publishes a metric based on the configured methods (VOLTTRON message bus and/or OTLP).

        Args:
            metric_name: The name of the metric (will be appended to the topic base)
            value: The value to publish
        """
        if self.publish_to_volttron:
            topic_base = f"{self.analytics_topic_prefix}/{self.gateway_name}"
            topic = f"{topic_base}/{metric_name}"
            self.vip.pubsub.publish("pubsub", topic, value)
            _log.debug(f"Published metric to VOLTTRON: {topic} = {value}")

        if self._meter is None:
            return

        try:
            numeric_value = float(value)
        except (ValueError, TypeError):
            _log.warning(f"Skipping non-numeric metric: {metric_name}={value}")
            return

        otel_name = f"bacnet_{metric_name.replace('/', '_')}"
        attrs = {"client": self.client, "site": self.site, "host": self.gateway_name}

        # Store the latest value — the observable gauge callback reads this on every
        # 30-second collection cycle, keeping the metric alive in Mimir between captures.
        self._metric_store[otel_name] = (numeric_value, attrs)

        if otel_name not in self._otlp_metrics:
            def make_callback(name: str):
                def callback(options):
                    if name in self._metric_store:
                        v, a = self._metric_store[name]
                        yield Observation(v, a)
                return callback

            self._otlp_metrics[otel_name] = self._meter.create_observable_gauge(
                otel_name,
                callbacks=[make_callback(otel_name)],
                description=f"BACnet metric: {metric_name}",
            )

    def _stop_periodic_tasks(self):
        """
        Stop all periodic tasks gracefully.
        This is called when the agent is stopping or reconfiguring.
        """
        keys_to_delete = []
        for file, process in self.captures.items():
            if process:
                _log.info(f"Killing existing packet capture process: {file}")
                process.send_signal(signal.SIGINT)
                process.kill()
                keys_to_delete.append(file)
        for key in keys_to_delete:
            del self.captures[key]
            _log.info(f"Removed {key} from captures dictionary")

        # Cancel existing tasks if they exist
        if self.capture_task:
            self.capture_task.kill()
        if self.upload_task:
            self.upload_task.kill()

    def _start_periodic_tasks(self):
        """
        Start periodic tasks for packet capture and upload.
        This is called when the agent starts or reconfigures.
        """
        # Start new tasks with updated configuration
        self.capture_task: gevent.Greenlet = self.core.periodic(
            self.capture_interval, self.packet_capture, wait=15
        )
        self.upload_task: gevent.Greenlet = self.core.periodic(
            self.upload_interval, self.upload_to_api, wait=5
        )

    def _restart_periodic_tasks(self):
        """
        Cancel and restart periodic tasks with updated configuration values.
        This is called when configuration changes or on agent startup.
        """
        self._stop_periodic_tasks()
        self._start_periodic_tasks()

        _log.info("Restarted periodic tasks with new configuration")

    def _cleanup_files(self):
        """
        Clean up old capture files to free up space.
        This method removes capture files older than a certain threshold.
        """
        try:
            threshold_time = datetime.now(timezone.utc) - timedelta(days=89)
            for file_path in glob.glob(f"{self.get_agent_data_path()}/*.pcap"):
                file_name = os.path.basename(file_path)
                if file_name not in self.captures:
                    file_time_str = file_name.split("_")[1]
                    file_time = datetime.strptime(
                        file_time_str, "%Y-%m-%dT%H-%M-%S"
                    ).replace(tzinfo=timezone.utc)
                    if file_time < threshold_time:
                        os.remove(file_path)
                        _log.info(f"Removed old capture file: {file_path}")
                    else:
                        self.compress_capture_file(
                            file_path
                        )  # Compress if not old enough
                        _log.info(f"Compressed capture file in cleanup: {file_path}")
        except Exception as exc:
            _log.error(f"Error cleaning up old capture files: {exc}")

    def check_free_space(self) -> bool:
        """
        Check if there is enough free space in the capture directory.
        Returns True if there is enough space, False otherwise.
        """

        # Check if there is enough free space in the capture directory.
        statvfs = os.statvfs(self.get_agent_data_path())
        free_space = statvfs.f_frsize * statvfs.f_bavail
        return free_space > 2**30  # Check if there is at least 1 GB of free space

    def get_capture_path(self, start_time: datetime):
        """
        Returns the path to the capture file.
        This is where the agent will store its packet captures.
        """
        # Assuming the default path for Volttron's data directory
        # You can customize this if your agent has a different data path.
        start_time_str = start_time.replace(second=0, microsecond=0).strftime(
            "%Y-%m-%dT%H-%M-%S"
        )
        end_time_str = (
            (start_time + timedelta(seconds=self.capture_duration))
            .replace(second=0, microsecond=0)
            .strftime("%Y-%m-%dT%H-%M-%S")
        )

        return os.path.join(
            self.get_agent_data_path(),
            f"{self.gateway_name}_{start_time_str}_{end_time_str}.pcap",
        )

    def compress_capture_file(self, capture_file: str):
        """
        Compress the capture file using gzip.
        This will create a .gz file with the same name as the capture file.
        :param capture_file: The path to the capture file.
        """
        with open(capture_file, "rb") as file:
            with open(f"{capture_file}.gz", "wb") as compressed_file:
                with gzip.GzipFile(fileobj=compressed_file, mode="wb") as gz:
                    gz.write(file.read())
        os.remove(capture_file)  # Remove the original file after compression

    def get_api_url(self) -> str:
        """
        Returns the API URL for uploading captured packets.
        If not set in the configuration, it raises an error.
        """
        config = self.get_default_config_from_agent_file()
        url = config.get("url", "https://flightdeck.tail8c70f.ts.net")
        return (
            f"{url}/api/gateways/{self.gateway_slug}/pcap"
        )

    def update_api_key_from_config(self) -> bool:
        """
        Update the API key from the ace-agent configuration file if it exists.
        """
        config = self.get_default_config_from_agent_file()
        if config and "jwt" in config:
            self.api_key = config["jwt"]
            _log.info("Updated API key from configuration")
            return True
        return False

    def upload_to_api(self) -> None:
        """
        Upload captured packets to ace API
        """
        # _log.debug("Attemping to collect files for upload")
        if self.upload_lock.locked():
            _log.debug("Upload lock is currently held, skipping upload.")
            return
        with self.upload_lock:
            for file_path in glob.glob(f"{self.get_agent_data_path()}/*.pcap.gz"):
                file_name = os.path.basename(file_path)
                gevent.sleep(2) # Rate limit uploading to API
                _log.debug(f"uploading to API... {self.api_url} {file_name=}")
                with open(file_path, "rb") as file:
                    filedata = file.read()
                try:
                    request = grequests.post(
                        self.get_api_url(),
                        files=(("file", (f"{file_name}", filedata)),),
                        headers={"Authorization": f"Bearer {self.api_key}"},
                    )
                    response = grequests.map(
                        [request], exception_handler=self.grequests_exception_handler
                    )[0]
                    if response is None:
                        _log.error(
                            "Failed to get a response from the API"
                        )
                        self.vip.health.set_status(
                            STATUS_BAD, "Failed to get a response from the API"
                        )
                        return
                    if response.status_code == 201:
                        _log.info(f"Upload successful: {response.text}")
                        os.remove(file_path)
                    elif response.status_code == 401:
                        _log.error(
                            f"Unauthorized: Invalid API key or token. {response.text}"
                        )
                        if self.update_api_key_from_config():
                            _log.info(
                                "Updated API key from configuration, retrying upload..."
                            )
                        else:
                            _log.error(
                                "Failed to update API key from configuration. Skipping upload."
                            )
                            self.vip.health.set_status(
                                STATUS_BAD, "Invalid API key or token."
                            )
                            return
                    else:
                        _log.error(
                            f"Upload failed: {response.status_code} {response.text}"
                        )
                except Exception as error:
                    _log.debug(f"{error=}")
                self.vip.health.set_status(STATUS_GOOD)

    def generate_port_list(self, ports) -> Union[str, None]:
        """
        Generate a string representation of the ports for tcpdump command
        :param ports: list of ports or a single port
        :return: string representation of the ports
        """
        if isinstance(ports, int):
            ports_list = str(ports)
        elif isinstance(ports, list):
            # use type() instead of isinstance(), since booleans inherit from int
            # prevents false negatives if list contains bool
            if not all(isinstance(p, int) for p in ports):
                _log.error("ports list contains non-integer")
                return None

            if len(ports) < 1:
                _log.error("no ports defined to scan on")
                return None
            ports_list = str(ports[0])
            for port in ports[1:]:
                ports_list += f" or port {port}"
        else:
            _log.error(f"port is not int or list: {type(ports)} {ports=}")
            return None
        return str(ports_list)

    def packet_capture(self) -> None:
        """
        Capture network packets on configured ports
        """
        if not self.check_free_space():
            _log.error("Not enough free space, skipping packet capture.")
            return
        _log.info("Starting packet capture...")
        capture_start_time = datetime.now(timezone.utc)
        ports_str = self.generate_port_list(self.ports)
        capture_file_path = self.get_capture_path(capture_start_time)

        command = (
            f"tcpdump -w {capture_file_path}"
            f" proto {self.protocol} and port {ports_str}"
        )
        if self.interface:
            command += f" -i {self.interface}"

        _log.info(f"capturing packets on ports {ports_str} for {self.capture_duration}s")
        try:
            this_capture = subprocess.Popen(
                args=command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.captures[capture_file_path] = this_capture
            # Send SIGINT after capture_duration so tcpdump flushes and closes cleanly.
            # SIGINT (not SIGKILL) lets tcpdump write the pcap trailer, preventing truncation.
            gevent.sleep(self.capture_duration)
            this_capture.send_signal(signal.SIGINT)
            retcode = this_capture.wait(timeout=10)
            if retcode not in (0, -2):  # 0 = clean exit, -2 = SIGINT (expected)
                _log.error(f"tcpdump command failed with return code {retcode}")
                self.vip.health.set_status(STATUS_BAD, f"tcpdump command failed with return code {retcode}")
                if this_capture.stdout is not None:
                    _log.error(
                        f"tcpdump command output: {this_capture.stdout.read().decode( 'utf-8')}"
                    )
                if this_capture.stderr is not None:
                    _log.error(
                        f"tcpdump command error: {this_capture.stderr.read().decode('utf-8')}"
                    )
                return
        except subprocess.TimeoutExpired:
            _log.warning("tcpdump did not exit after SIGINT, force-killing...")
            this_capture.kill()
            this_capture.wait()
            _log.info("tcpdump process force-killed.")
            self.vip.health.set_status(STATUS_BAD, "tcpdump did not exit cleanly after SIGINT")
        except Exception as error:
            if hasattr(error, "stderr"):
                _log.error(f"cannot execute tcpdump command: {error} - {error.stderr}")
            else:
                _log.error(f"cannot execute tcpdump command {error}")
            self.vip.health.set_status(STATUS_BAD, f"cannot execute tcpdump command: {error}")
            return
        else:
            _log.info("tcpdump command completed successfully.")
            self.vip.health.set_status(STATUS_GOOD)
        finally:
            self.core.schedule(
                datetime.now() + timedelta(seconds=5), self._cleanup_files
            )
        # check for empty capture file, handle accordingly
        if os.path.getsize(capture_file_path) == 0:
            _log.warning(
                f"Captured file {capture_file_path} is empty, skipping analytics and compression."
            )
            os.remove(capture_file_path)
            return

        # Run analytics on the captured file if enabled
        if self.analytics_enabled:
            _log.info(
                f"Running analytics on the newly captured file {capture_file_path}"
            )
            # Run analytics before compression so we can process the pcap directly
            try:
                self.process_analytics(capture_file_path)
            except Exception as exc:
                trace = traceback.format_exc()
                _log.error(f"Error in process_analytics: {trace}")
                _log.error(f"Error processing analytics: {exc}")

        self.compress_capture_file(capture_file_path)  # Compress the capture file
        _log.info(f"Packet capture completed and {capture_file_path} compressed.")

    def process_analytics(self, pcap_file_path: str) -> None:
        """
        Process a specific pcap file using bp-pcap-tools and publish metrics.

        This method processes a pcap file using the bp-pcap-tools library
        and publishes metrics to the VOLTTRON message bus.

        Args:
            pcap_file_path: Path to the pcap file to process
        """

        try:
            # Initialize broadcast addresses if needed
            if self.broadcast_addrs is None:
                self.broadcast_addrs = get_local_broadcast()
                _log.info(f"Detected broadcast addresses: {self.broadcast_addrs}")

            # Process the pcap file
            _log.info(f"Processing pcap file for analytics: {pcap_file_path}")
            results = process_pcap(pcap_file_path, self.broadcast_addrs)
            # _log.debug( f"Processed results: {results}")

            # Generate network scores
            scores = generate_scores(
                results["traffic_counter"],
                results["traffic_type_counter"],
                results["dest_type_counter"],
                results["global_whois"],
            )

            # Publish metrics

            # Publish overall network score
            self.publish_metric("score", scores["total_score"])

            # Publish component scores
            self.publish_metric("broadcast_ratio", scores["broadcast_ratio"])
            self.publish_metric(
                "local_broadcast_ratio", scores["local_broadcast_ratio"]
            )
            self.publish_metric("remote_station_ratio", scores["remote_station_ratio"])
            self.publish_metric("whois_ratio", scores["whois_ratio"])
            self.publish_metric("prop_acked_ratio", scores["prop_acked_ratio"])
            self.publish_metric("props_acked_ratio", scores["props_acked_ratio"])

            # Publish traffic statistics
            self.publish_metric("packet_count", results["packet_count"])
            self.publish_metric("device_count", len(results["address_map"]))

            # Publish message type counts — ensure known types always exist in Mimir
            # even if they didn't appear in this capture, so the Acked State panel
            # can find them for its count() > 0 gating condition.
            known_msg_types = {
                "ReadPropertyACK", "ReadPropertyMultipleACK",
                "ReadPropertyRequest", "ReadPropertyMultipleRequest",
                "WhoIsRequest", "WhoHasRequest",
            }
            for msg_type in known_msg_types - results["traffic_type_counter"].keys():
                self.publish_metric(f"message_types/{msg_type}", 0)
            for msg_type, count in results["traffic_type_counter"].items():
                self.publish_metric(f"message_types/{msg_type}", count)

            # Publish destination type counts
            for dest_type, count in results["dest_type_counter"].items():
                self.publish_metric(f"destination_types/{dest_type}", count)

            _log.info(
                f"Published analytics with overall score: {scores['total_score']}"
            )

        except Exception as exc:
            _log.error(f"Error processing analytics: {exc}")

    def grequests_exception_handler(self, request, exception):
        """
        Handle exceptions for grequests.
        This is called when a request fails.
        """
        _log.error(f"Request failed: {request.url} with exception: {exception}")

    @Core.receiver("onstart")
    def onstart(self, sender, **kwargs):
        """
        This is called once the Agent has successfully connected to the platform.
        This is a good place to setup subscriptions if they are not dynamic or
        do any other startup activities that require a connection to the message bus.
        Called after any configurations methods that are called at startup.

        Usually not needed if using the configuration store.
        """
        _exporter = OTLPMetricExporter(endpoint="http://localhost:4318/v1/metrics")
        _reader = PeriodicExportingMetricReader(_exporter, export_interval_millis=30_000)
        self._meter_provider = MeterProvider(metric_readers=[_reader], resource=Resource.create({"service.name": self.core.identity}))
        otel_metrics.set_meter_provider(self._meter_provider)
        self._meter = self._meter_provider.get_meter("ace.packet_capture", version=__version__)
        _log.info("OTLP metrics publisher started, pushing to http://localhost:4318/v1/metrics")
        _log.info("Agent starting, waiting for configuration to be loaded. ")

        # Initialize data directory
        # self.initialize_data_path(self.get_agent_data_path())

        # Start periodic tasks
        # self._restart_periodic_tasks()

    @Core.receiver("onstop")
    def onstop(self, sender, **kwargs):
        """
        This method is called when the Agent is about to shutdown,
        but before it disconnects from the message bus.
        """
        _log.info("Agent is stopping. Cancelling periodic tasks...")
        self._stop_periodic_tasks()
        if self._meter_provider is not None:
            self._meter_provider.shutdown()


def main():
    """Main method called to start the agent."""
    utils.vip_main(packet_capture, version=__version__)
    _log.info("PacketCapture agent starting...")


if __name__ == "__main__":
    # Entry point for script
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
