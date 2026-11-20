import ipaddress
import logging

logger = logging.getLogger(__name__)


class PatternBase:
    def __init__(self):
        self.enabled = True
        # self.whitelist lo asigna el decorador @pattern (config["WHITELIST"])
        self.whitelist_networks = self._parse_whitelist(getattr(self, "whitelist", []))

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    @staticmethod
    def _parse_whitelist(entries):
        # Acepta lista o texto separado por comas; IPs sueltas o rangos CIDR
        if isinstance(entries, str):
            entries = entries.split(",")

        redes = []
        for entry in entries or []:
            entry = str(entry).strip()
            if not entry:
                continue
            try:
                redes.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                logger.error("Entrada de WHITELIST no válida, se ignora: %r", entry)
        return redes

    def _in_whitelist(self, ip):
        try:
            direccion = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(direccion in red for red in self.whitelist_networks)