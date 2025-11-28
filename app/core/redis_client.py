import redis
from app.config import settings
from typing import Optional

redis_client: Optional[redis.Redis] = None


def get_redis() -> redis.Redis:
    global redis_client
    if redis_client is None:
        redis_client = redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5
        )
    return redis_client

