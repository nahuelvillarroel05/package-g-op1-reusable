"""Capability profiles for Package G V2 advisory dryruns."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict


@dataclass(frozen=True)
class CapabilityProfile:
    name: str
    can_read_reports: bool = False
    can_read_source: bool = False
    can_write_report_artifacts: bool = False
    can_create_dataset_preview: bool = False
    can_create_dataset_canonical: bool = False
    can_train_model: bool = False
    can_use_sklearn: bool = False
    can_use_torch: bool = False
    can_use_tensorflow: bool = False
    can_use_transformers: bool = False
    can_use_lora: bool = False
    can_use_langchain: bool = False
    can_use_embeddings: bool = False
    can_use_vector_index: bool = False
    can_read_market_data: bool = False
    can_use_network: bool = False
    can_write_onedrive: bool = False
    can_write_d_tree: bool = False

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

    def dangerous_capabilities(self) -> Dict[str, bool]:
        keys = (
            "can_create_dataset_canonical",
            "can_train_model",
            "can_use_sklearn",
            "can_use_torch",
            "can_use_tensorflow",
            "can_use_transformers",
            "can_use_lora",
            "can_use_langchain",
            "can_use_embeddings",
            "can_use_vector_index",
            "can_read_market_data",
            "can_use_network",
            "can_write_onedrive",
            "can_write_d_tree",
        )
        return {key: bool(getattr(self, key)) for key in keys}

    def assert_dangerous_disabled(self) -> None:
        enabled = [key for key, value in self.dangerous_capabilities().items() if value]
        if enabled:
            raise ValueError(f"Dangerous capabilities enabled: {enabled}")


def BaseReadOnlyProfile() -> CapabilityProfile:
    return CapabilityProfile(name="BaseReadOnlyProfile", can_read_reports=True)


def ScorerProfile() -> CapabilityProfile:
    return CapabilityProfile(
        name="ScorerProfile",
        can_read_reports=True,
        can_write_report_artifacts=True,
    )


def OrchestratorDryRunProfile() -> CapabilityProfile:
    return CapabilityProfile(
        name="OrchestratorDryRunProfile",
        can_read_reports=True,
        can_read_source=True,
        can_write_report_artifacts=True,
        can_create_dataset_preview=True,
    )


def DatasetPreviewProfile() -> CapabilityProfile:
    return CapabilityProfile(
        name="DatasetPreviewProfile",
        can_read_reports=True,
        can_write_report_artifacts=True,
        can_create_dataset_preview=True,
    )


def FutureTrainingProfileLocked() -> CapabilityProfile:
    return CapabilityProfile(name="FutureTrainingProfileLocked")
