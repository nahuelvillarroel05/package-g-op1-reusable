"""Locked model adapter contracts for Package G V2."""
from __future__ import annotations


class ModelAdapterRejected(RuntimeError):
    pass


class NoOpModelAdapter:
    authorized = False
    adapter_name = "NoOpModelAdapter"

    def fit(self, *args, **kwargs):
        raise ModelAdapterRejected("Model fitting is not authorized in Package G V2 dryrun")

    def predict(self, *args, **kwargs):
        raise ModelAdapterRejected("Model prediction is not authorized in Package G V2 dryrun")


class _LockedAdapter(NoOpModelAdapter):
    adapter_name = "LockedAdapter"


class SklearnModelAdapter(_LockedAdapter):
    adapter_name = "SklearnModelAdapter"


class TorchModelAdapter(_LockedAdapter):
    adapter_name = "TorchModelAdapter"


class TensorFlowModelAdapter(_LockedAdapter):
    adapter_name = "TensorFlowModelAdapter"


class TransformersModelAdapter(_LockedAdapter):
    adapter_name = "TransformersModelAdapter"


class LoRAAdapter(_LockedAdapter):
    adapter_name = "LoRAAdapter"


class LangChainAdapter(_LockedAdapter):
    adapter_name = "LangChainAdapter"
