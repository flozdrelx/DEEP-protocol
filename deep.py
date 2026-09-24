import sys
import logging
from pathlib import Path
from urllib.parse import urlparse
from resolver import resolve

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "deep.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("DEEP")

def main():
    logger.info("DEEP started")

    if len(sys.argv) < 2:
        logger.warning("No URI was provided")
        return

    uri = sys.argv[1]
    logger.info("Received URI: %s", uri)

    parsed = urlparse(uri)

    if parsed.scheme != "deep":
        logger.error("Invalid protocol: %s", parsed.scheme)
        return

    host = parsed.netloc
    path = parsed.path or "/"

    logger.info("Network: %s", host)
    logger.info("Resource: %s", path)

    result = resolve(host, path)

    logger.info(
        "Resolution result: status=%s message=%s",
        result["status"],
        result["message"]
    )

    print("=== DEEP PROTOCOL ===")
    print(f"Network : {host}")
    print(f"Resource: {path}")
    print(f"Status  : {result['status']}")
    print(f"Message : {result['message']}")


if __name__ == "__main__":
    main()