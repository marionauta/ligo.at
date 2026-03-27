from abc import ABC, abstractmethod
from logging import Logger
from typing import Generic, TypeVar, override

K = TypeVar("K", bound=str)
V = TypeVar("V", bound=str)


class KV(ABC, Generic[K, V]):
    @abstractmethod
    def get(self, key: K) -> V | None:
        pass

    @abstractmethod
    def set(self, key: K, value: V):
        pass


class _NoKV(KV):
    logger: Logger = Logger(__name__)

    @override
    def get(self, key: str) -> str | None:
        self.logger.debug(f"NoKV get({key})")
        return None

    @override
    def set(self, key: str, value: str):
        self.logger.debug(f"NoKV set({key}, {value})")
        pass


nokv = _NoKV()
