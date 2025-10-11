from abc import ABC, abstractmethod
from typing import override


class KV(ABC):
    @abstractmethod
    def get(self, key: str) -> str | None:
        pass

    @abstractmethod
    def set(self, key: str, value: str):
        pass


class NoKV(KV):
    @override
    def get(self, key: str) -> str | None:
        return None

    @override
    def set(self, key: str, value: str):
        pass


nokv = NoKV()
