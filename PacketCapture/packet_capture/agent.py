"""
Cristian Romo
cristian@aceiotsolutions.com

Capture network packets on a configurable protocol and port list
Enable upload of packet captures to a given API

"""

__docformat__ = "reStructuredText"

import glob
import gzip
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone, timedelta

import gevent
import grequests
from volttron.platform.agent import utils
from volttron.platform.messaging.health import STATUS_BAD, STATUS_GOOD
from volttron.platform.vip.agent import RPC, Agent, Core

_log = logging.getLogger(__name__)
utils.setup_logging()
__version__ = "1.1.0"


def packet_capture(config_path, **kwargs):
    """
    Parses the Agent configuration and returns an instance of
    the agent created using that configuration.

    :param config_path: Path to a configuration file.
    :type config_path: str
    :returns: PacketCapture
    :rtype: PacketCapture
    """
    try:
        config = utils.load_config(config_path)
    except Exception:
        config = {}

    capture_duration = config.get("capture_duration", 300)
    capture_interval = config.get("capture_interval", 60 * 60)
    interface = config.get("interface")
    capture_file = config.get("capture_file", "/var/lib/volttron/default_capture.pcap")
    protocol = config.get("protocol", "UDP")
    ports = config.get("ports", 47808)
    _log.debug(f"found {ports=} from config")
    api_key = config.get("api_key")
    api_url = config.get("api_url", "https://app.visualbacnet.com/api/v2/upload")

    return PacketCapture(
        capture_duration,
        capture_interval,
        interface,
        capture_file,
        protocol,
        ports,
        api_key,
        api_url,
        **kwargs,
    )


class PacketCapture(Agent):
    """
    Document agent constructor here.
    """

    def __init__(
        self,
        capture_duration,
        capture_interval,
        interface,
        capture_file,
        protocol,
        ports,
        api_key,
        api_url,
        **kwargs,
    ):
        super(PacketCapture, self).__init__(**kwargs)
        self.capture_duration = capture_duration
        self.capture_interval = capture_interval
        self.interface = interface
        self.capture_file = capture_file
        self.protocol = protocol
        self.ports = ports
        self.api_key = api_key
        self.api_url = api_url
        self.config_store = {}
        self.capture_lock = gevent.lock.BoundedSemaphore()
        self.upload_lock = gevent.lock.BoundedSemaphore()

    def configure(self, config_name, action, contents):
        """
        Called after the Agent has connected to the message bus.
        If a configuration exists at startup this will be called before onstart.

        Is called every time the configuration in the store changes.
        """

    def get_agent_data_path(self) -> str:
        """
        Returns the path to the agent's data directory.
        This is where the agent can store its state.
        """
        # Assuming the default path for Volttron's data directory
        # You can customize this if your agent has a different data path.
        if self.data_path is not None:
            return self.data_path
        data_path = os.path.join(os.getcwd(), os.path.basename(os.getcwd()) + ".agent-data")
        if os.path.exists(data_path):
            return data_path
        return os.getcwd()

    def get_capture_path(self, start_time: datetime):
        """
        Returns the path to the capture file.
        This is where the agent will store its packet captures.
        """
        # Assuming the default path for Volttron's data directory
        # You can customize this if your agent has a different data path.
        start_time_str = start_time.replace(second=0, microsecond=0).isoformat()
        end_time_str = (
            (start_time + timedelta(seconds=self.capture_duration))
            .replace(second=0, microsecond=0)
            .isoformat()
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

    def upload_to_api(self) -> None:
        """
        Upload captured packets to ace API
        """
        with self.upload_lock:
            _log.debug(f"uploading to API... {self.api_url}")
            for file_path in glob.glob(f"{self.get_agent_data_path()}/*.pcap.gz"):
                file_name = os.path.basename(file_path)
                with open(file_path, "rb") as file:
                    filedata = file.read()
                try:
                    request = grequests.post(
                        self.api_url,
                        files=(
                            ("apiKey", (None, self.api_key)),
                            ("file", (f"{os.uname()[1]}:{file_name}", filedata)),
                        ),
                    )
                    (response,) = grequests.map((request,))
                    _log.info(f"finished uploading: {response.status_code}")
                    if response.status_code == 201:
                        _log.info(f"Upload successful: {response.text}")
                        os.remove(file_path)
                except Exception as error:
                    _log.debug(f"{error=}")

    def generate_port_list(self, ports) -> str | None:
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
            if not all((type(p) is int) for p in ports):
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
        if self.capture_lock.locked():
            _log.info("Previous capture has not completed. Skipping packet capture")
            return
        with self.capture_lock:
            _log.info("Starting packet capture...")
            capture_start_time = datetime.now(timezone.utc)
            ports_str = self.generate_port_list(self.ports)
            capture_file_path = self.get_capture_path(capture_start_time)

            command = f"""tcpdump -G {self.capture_duration} -W 1 -w {capture_file_path} proto {self.protocol} and port {ports_str}"""
            if self.interface:
                command += f" -i {self.interface}"

            _log.info(f"capturing packets on ports {ports_str}")
            try:
                subprocess.run(
                    command,
                    shell=True,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except subprocess.CalledProcessError as error:
                _log.error(f"cannot execute tcpdump command: {error.stderr}")
                return
            self.compress_capture_file(capture_file_path)  # Compress the capture file
            _log.info(f"Packet capture completed and {capture_file_path} compressed.")

    def _handle_publish(self, peer, sender, bus, topic, headers, message):
        """
        Callback triggered by the subscription setup using
        the topic from the agent's config file
        """

    @Core.receiver("onstart")
    def onstart(self, sender, **kwargs):
        """
        This is called once the Agent has successfully connected to the platform.
        This is a good place to setup subscriptions if they are not dynamic or
        do any other startup activities that require a connection to the message bus.
        Called after any configurations methods that are called at startup.

        Usually not needed if using the configuration store.
        """
        _log.info(
            f"Config loaded and starting capture loop every {self.capture_interval}, for {self.capture_duration}"
        )
        self.core.periodic(self.capture_interval, self.packet_capture, wait=15)
        self.core.periodic(self.capture_interval, self.upload_to_api, wait=5)

    @Core.receiver("onstop")
    def onstop(self, sender, **kwargs):
        """
        This method is called when the Agent is about to shutdown,
        but before it disconnects from the message bus.
        """


def main():
    """Main method called to start the agent."""
    utils.vip_main(packet_capture, version=__version__)


if __name__ == "__main__":
    # Entry point for script
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
