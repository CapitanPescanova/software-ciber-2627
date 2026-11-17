import json
import logging
import os
import signal
import time
from pathlib import Path
from threading import Event, Thread

import util.health
from util.config_loader import config
from util.health import RECEIVED_LOG_FILE, file_lock
from util.log_parser import parse_log_lines
from util.log_storage import ParsedLogStorage
from util.parsers import parse_rules


logger = logging.getLogger(__name__)


def _truncate_log_file(log_path: Path):
    with file_lock:
        with log_path.open("w", encoding="utf-8"):
            pass


def _process_log_batch(log_path: Path, rules, storage):
    with file_lock:
        try:
            contents = log_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return False
        except OSError as error:
            logger.warning("No se pudo leer %s: %s", log_path, error)
            return False

    if not contents.strip():
        return False

    logger.info("Nuevos logs detectados. Iniciando ejecución de la app IDS...")
    try:
        eventos = parse_log_lines(contents.splitlines())
        storage.save_many(eventos)

        detecciones = []
        for rule in rules:
            if rule.enabled:
                detecciones.extend(rule.run(eventos))
            else:
                logger.info("---Regla %s desactivada---", rule.pattern_id)

        events_path = Path(__file__).resolve().parents[1] / "output"
        events_path.mkdir(parents=True, exist_ok=True)
        with open(events_path / "events.json", "w", encoding="utf-8") as file:
            json.dump(detecciones, file, indent=2)
    except Exception as error:
        logger.exception(
            "Error durante el análisis del IDS: %s. Truncando para continuar.",
            error,
        )
    finally:
        try:
            logger.info("App IDS finalizada. Truncando archivo de logs.")
            _truncate_log_file(log_path)
        except FileNotFoundError:
            pass
        except OSError as error:
            logger.warning("No se pudo truncar %s: %s", log_path, error)

    return True


def _poll_logs(stop_event: Event, rules, storage, log_path: Path, interval: float):
    waiting_logged = False

    while True:
        if stop_event.is_set():
            break

        has_logs = _process_log_batch(log_path, rules, storage)

        if not has_logs:
            if not waiting_logged:
                logger.info("Esperando nuevos logs en %s...", log_path)
                waiting_logged = True
        else:
            waiting_logged = False

        time.sleep(interval)

    logger.info("Cerrando bucle de polling del IDS.")


def main():
    logging.basicConfig(level=logging.INFO)
    stop_event = Event()

    def request_shutdown(signum, _frame):
        logger.info("Señal %s recibida. Cerrando IDS...", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)

    app = Thread(
        target=util.health.app.run,
        kwargs={"port": 80, "host": "0.0.0.0"},
        daemon=True,
    )
    app.start()

    rules = parse_rules("config/ids.rules")

    for rule in rules:
        if rule.pattern_id == "P002":
            rule.disable()

    storage = ParsedLogStorage()
    try:
        interval = float(os.getenv("IDS_POLL_INTERVAL", "5"))
    except ValueError:
        logger.warning("IDS_POLL_INTERVAL no es válido; se usará 5 segundos.")
        interval = 5

    if interval < 0:
        logger.warning("IDS_POLL_INTERVAL no puede ser negativo; se usará 5 segundos.")
        interval = 5

    logger.info("Log a procesar: %s", RECEIVED_LOG_FILE)
    logger.info("Whitelist: %s", config["WHITELIST"])
    polling = Thread(
        target=_poll_logs,
        args=(stop_event, rules, storage, RECEIVED_LOG_FILE, interval),
        daemon=True,
    )
    polling.start()

    try:
        stop_event.wait()
    except KeyboardInterrupt:
        stop_event.set()

    polling.join()


if __name__ == "__main__":
    main()
