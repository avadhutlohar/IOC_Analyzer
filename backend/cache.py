import os
import json
import time
import aiosqlite
import redis.asyncio as redis

DB_FILE = "cache.db"
CACHE_TTL = 3600  # 1 hour

USE_REDIS = os.getenv("USE_REDIS", "false").lower() == "true"
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

redis_client = None


async def init_cache():
    global redis_client
    if USE_REDIS:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    else:
        async with aiosqlite.connect(DB_FILE) as db:
            await db.execute(
                "CREATE TABLE IF NOT EXISTS cache (ioc TEXT PRIMARY KEY, data TEXT, timestamp INTEGER)"
            )
            await db.commit()


async def get_cache(key: str):
    if USE_REDIS and redis_client:
        data = await redis_client.get(key)
        return json.loads(data) if data else None

    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT data, timestamp FROM cache WHERE ioc = ?", (key,)) as cursor:
            row = await cursor.fetchone()
            if row:
                data, ts = row
                if time.time() - ts < CACHE_TTL:
                    return json.loads(data)
    return None


async def set_cache(key: str, data: dict):
    if USE_REDIS and redis_client:
        await redis_client.setex(key, CACHE_TTL, json.dumps(data))
        return

    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT OR REPLACE INTO cache (ioc, data, timestamp) VALUES (?, ?, ?)",
            (key, json.dumps(data), int(time.time())),
        )
        await db.commit()
