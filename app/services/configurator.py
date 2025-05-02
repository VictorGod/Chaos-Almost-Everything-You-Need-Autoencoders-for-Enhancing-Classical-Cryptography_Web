from app.schemas import ConfigOptions


class CryptoConfigurator:
    def __init__(self):
        self._core = "python"
        self._entropy = "system"
        self._retrain = False

    def set_core(self, core: str):
        self._core = core
        return self

    def set_entropy_source(self, source: str):
        self._entropy = source
        return self

    def set_retrain(self, flag: bool):
        self._retrain = flag
        return self

    def build(self) -> ConfigOptions:
        return ConfigOptions(
            core_type=self._core,
            entropy_source=self._entropy,
            retrain_autoencoder=self._retrain,
        )
