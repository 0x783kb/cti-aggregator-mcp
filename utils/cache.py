"""
Simple Async TTL Cache Implementation
"""
import time
import asyncio
from typing import Any, Dict, Optional, Tuple

class TTLCache:
    def __init__(self, default_ttl: int = 3600):
        """
        初始化 TTL 缓存
        :param default_ttl: 默认过期时间 (秒)，默认 1 小时
        """
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self.default_ttl = default_ttl
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        """
        获取缓存值
        """
        async with self._lock:
            if key not in self._cache:
                return None
            
            value, expiry = self._cache[key]
            if time.time() > expiry:
                del self._cache[key]
                return None
            
            return value

    async def set(self, key: str, value: Any, ttl: int = None):
        """
        设置缓存值
        """
        ttl = ttl if ttl is not None else self.default_ttl
        expiry = time.time() + ttl
        async with self._lock:
            self._cache[key] = (value, expiry)

    async def delete(self, key: str):
        """
        删除缓存
        """
        async with self._lock:
            if key in self._cache:
                del self._cache[key]

    async def clear(self):
        """
        清空缓存
        """
        async with self._lock:
            self._cache.clear()

    async def cleanup(self):
        """
        清理过期键 (可定期调用)
        """
        now = time.time()
        async with self._lock:
            keys_to_delete = [k for k, (v, exp) in self._cache.items() if now > exp]
            for k in keys_to_delete:
                del self._cache[k]
