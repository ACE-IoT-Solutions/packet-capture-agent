"""
Cristian Romo
cristian@aceiotsolutions.com

Capture network packets on a configurable protocol and port list
Enable upload of packet captures to a given API

"""

__docformat__ = "reStructuredText"

import logging
import sys
import subprocess
import os

import gevent
import grequests
from volttron.platform.agent import utils
from volttron.platform.messaging.health import STATUS_BAD, STATUS_GOOD
from volttron.platform.vip.agent import Agent, Core, RPC

_log = logging.getLogger(__name__)
utils.setup_logging()
__version__ = "1.0.0"


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

    capture_interval = config.get("capture_interval", 300)
    scan_interval = config.get("scan_interval", 60 * 60)
    interface = config.get("interface")
    capture_file = config.get("capture_file", "/var/lib/volttron/default_capture.pcap")
    protocol = config.get("protocol", "UDP")
    ports = config.get("ports", 47808)
    _log.debug(f"found {ports=} from config")
    api_key = config.get("api_key")
    api_url = config.get("api_url", "https://app.visualbacnet.com/api/v2/upload")

    return PacketCapture(
        capture_interval,
        scan_interval,
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
        capture_interval,
        scan_interval,
        interface,
        capture_file,
        protocol,
        ports,
        api_key,
        api_url,
        **kwargs,
    ):
        super(PacketCapture, self).__init__(**kwargs)
        self.capture_interval = capture_interval
        self.scan_interval = scan_interval
        self.interface = interface
        self.capture_file = capture_file
        self.protocol = protocol
        self.ports = ports
        self.api_key = api_key
        self.api_url = api_url
        self.config_store = {}
        self.lock = gevent.lock.BoundedSemaphore()

    def configure(self, config_name, action, contents):
        """
        Called after the Agent has connected to the message bus.
        If a configuration exists at startup this will be called before onstart.

        Is called every time the configuration in the store changes.
        """

    def upload_to_api(self):
        """
        Upload captured packets to visualbacnet API
        """
        self.lock.acquire()
        _log.debug(f"uploading to API... {self.api_url}")
        with open(self.capture_file, "rb") as file:
            filedata = file.read()
        try:
            request = grequests.post(
                self.api_url,
                files=(
                    ("apiKey", (None, self.api_key)),
                    ("file", (f"{os.uname()[1]}:{self.capture_file}", filedata)),
                ),
            )
            (response,) = grequests.map((request,))
            _log.info(f"finished uploading: {response.status_code}")
        except Exception as error:
            _log.debug(f"{error=}")
            self.lock.release()
        self.lock.release()

    def packet_capture(self):
        """
        Capture network packets on configured ports
        """
        if self.lock.locked():
            _log.info("File upload not yet finished. Skipping packet capture")
            return

        if isinstance(self.ports, int):
            ports_list = self.ports
        elif isinstance(self.ports, list):
            ports_list = str(self.ports[0])
            if not ports_list:
                _log.error("no ports defined to scan on")
                return None
            for port in self.ports[1:]:
                ports_list += f" or port {port}"
        else:
            _log.error(f"port is not int or list: {type(self.ports)} {self.ports=}")

        command = f"""tcpdump -G {self.capture_interval} -W 1 -w {self.capture_file} proto {self.protocol} and port {ports_list}"""
        if self.interface:
            command += f" -i {self.interface}"

        _log.info(f"capturing packets on ports {ports_list}")
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

        self.upload_to_api()

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

        self.core.periodic(self.scan_interval, self.packet_capture, wait=15)

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
