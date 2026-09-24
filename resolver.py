import json
import logging
from pathlib import Path


CONFIG_FILE = Path(__file__).parent / "config.json"

logger = logging.getLogger("DEEP")


def load_config():
    logger.info("Loading configuration: %s", CONFIG_FILE)

    with open(CONFIG_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def resolve(network, path):
    logger.info("Resolving network: %s", network)

    config = load_config()
    networks = config.get("networks", {})

    if network not in networks:
        logger.warning("Network not found: %s", network)

        return {
            "status": 404,
            "message": f"Network '{network}' was not found."
        }

    network_data = networks[network]

    logger.info(
        "Found network '%s' at %s",
        network_data["name"],
        network_data["endpoint"]
    )

    return {
        "status": 200,
        "message": (
            f"Connected to {network_data['name']} "
            f"at {network_data['endpoint']}{path}"
        )
    }