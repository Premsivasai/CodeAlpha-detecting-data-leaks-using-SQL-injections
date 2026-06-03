import time
from typing import Optional


SLIDING_WINDOW_LUA = """
local current = redis.call('INCR', KEYS[1])
if tonumber(current) == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""


async def allow_request(redis, key: str, limit: int, window_seconds: int) -> bool:
    """Simple atomic check using INCR+EXPIRE in Lua. Returns True if under limit."""
    if redis is None:
        return True

    try:
        # Use EVAL to ensure INCR and EXPIRE are atomic
        current = await redis.eval(SLIDING_WINDOW_LUA, 1, key, window_seconds)
        try:
            current = int(current)
        except Exception:
            current = 0
        return current <= limit
    except Exception:
        # On any redis error, allow the request (fail-open) and let fallback enforce
        return True
