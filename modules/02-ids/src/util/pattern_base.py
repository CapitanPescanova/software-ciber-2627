##Initialization of the patterns' state (enabled/disabled)


class PatternBase:
    def __init__(self, enabled: bool = True):
        if isinstance(enabled, str):
            self.enabled = enabled.strip().lower() in ("1", "true", "yes", "on", "enabled")
        else:
            self.enabled = bool(enabled)

    def enable(self) -> None:
        self.enabled = True

    def disable(self) -> None:
        self.enabled = False

    def is_enabled(self) -> bool:
        return bool(self.enabled)