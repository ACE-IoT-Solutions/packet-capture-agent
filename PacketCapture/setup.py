from setuptools import find_packages, setup

MAIN_MODULE = "agent"

# Find the agent package that contains the main module
packages = find_packages(".")
agent_package = "packet_capture"

# Find the version number from the main module
agent_module = agent_package + "." + MAIN_MODULE
_temp = __import__(agent_module, globals(), locals(), ["__version__"], 0)
__version__ = _temp.__version__

# Setup
setup(
    name=agent_package + "agent",
    version=__version__,
    author="Cristian Romo",
    author_email="cristian@aceiotsolutions.com",
    install_requires=[
        "volttron",
        "pyshark",
        "bacpypes>=0.16.7,<0.20.0",
        "netifaces",
        "nest_asyncio",
        "networkx",
        "pyvis",
        "prometheus_client",
    ],
    packages=packages,
    package_data={agent_package: ["config"]},
    entry_points={
        "setuptools.installation": [
            "eggsecutable = " + agent_module + ":main",
        ]
    },
)
