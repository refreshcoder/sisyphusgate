from __future__ import annotations

import os
import time

from sisyphusgate.utils.logging import get_logger

logger = get_logger(__name__)


class GeoIPResolver:
    def __init__(self, db_path: str | None = None):
        self._db_path = db_path
        self._reader = None
        self._cache: dict[str, tuple[str, str, float]] = {}
        self._cache_ttl = 3600
        self._enabled = False

    async def start(self) -> None:
        if not self._db_path or not os.path.exists(self._db_path):
            logger.warning("geoip_db_not_found", path=self._db_path, message="GeoIP disabled")
            return

        try:
            import geoip2.database
            import geoip2.errors

            self._reader = geoip2.database.Reader(self._db_path)
            self._enabled = True
            logger.info("geoip_resolver_started", db_path=self._db_path)
        except ImportError:
            logger.warning("geoip2_not_installed", message="Install geoip2 package for GeoIP support")
        except Exception:
            logger.exception("geoip_init_error")

    async def stop(self) -> None:
        if self._reader:
            self._reader.close()
            self._reader = None
        self._enabled = False

    def resolve(self, ip: str) -> tuple[str, str, float, float]:
        if ip in self._cache:
            country, city, lat, lng, cached_at = self._cache[ip]
            if time.time() - cached_at < self._cache_ttl:
                return country, city, lat, lng

        if not self._enabled or not self._reader:
            return "", "", 0.0, 0.0

        try:
            response = self._reader.city(ip)
            country = response.country.iso_code or ""
            city = response.city.name or ""
            lat = response.location.latitude or 0.0
            lng = response.location.longitude or 0.0

            self._cache[ip] = (country, city, lat, lng, time.time())
            return country, city, lat, lng
        except Exception:
            return "", "", 0.0, 0.0

    @property
    def is_enabled(self) -> bool:
        return self._enabled