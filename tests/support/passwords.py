from app.core.passwords import Argon2Params, PasswordHasher

# Cheapest parameters argon2 accepts: keeps API tests fast.
# Production parameters are covered by tests/unit/test_passwords.py.
FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8, parallelism=1)
STRONG_PASSWORD = "violet piano under the stairs"


def fast_hasher() -> PasswordHasher:
    return PasswordHasher(FAST_PARAMS)
