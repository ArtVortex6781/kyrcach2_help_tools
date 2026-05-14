from __future__ import annotations

import pytest

from mesh_crypto.errors import InvalidSessionStateError, SessionCounterError
from mesh_crypto.sessions.chains import (
    advance_chain,
    derive_message_key,
    derive_next_chain_key,
)

UINT64_MAX = 2 ** 64 - 1


def make_chain_key(value: bytes = b"c") -> bytes:
    return value * 32


class TestDeriveMessageKey:
    def test_derive_message_key_returns_32_bytes(self) -> None:
        message_key = derive_message_key(make_chain_key(), 0)

        assert isinstance(message_key, bytes)
        assert len(message_key) == 32

    def test_derive_message_key_is_deterministic_for_same_inputs(self) -> None:
        chain_key = make_chain_key()

        first = derive_message_key(chain_key, 7)
        second = derive_message_key(chain_key, 7)

        assert first == second

    def test_derive_message_key_changes_with_counter(self) -> None:
        chain_key = make_chain_key()

        first = derive_message_key(chain_key, 1)
        second = derive_message_key(chain_key, 2)

        assert first != second

    @pytest.mark.parametrize(
        "bad_chain_key",
        [
            b"",
            b"x" * 31,
            b"x" * 33,
            "x" * 32,
            None,
        ],
    )
    def test_invalid_chain_key_raises_invalid_session_state_error(self, bad_chain_key) -> None:
        with pytest.raises(InvalidSessionStateError):
            derive_message_key(bad_chain_key, 0)

    @pytest.mark.parametrize(
        "bad_counter",
        [
            -1,
            2 ** 64,
            "0",
            None,
            True,
            False,
        ],
    )
    def test_invalid_counter_raises_session_counter_error(self, bad_counter) -> None:
        with pytest.raises(SessionCounterError):
            derive_message_key(make_chain_key(), bad_counter)


class TestDeriveNextChainKey:
    def test_derive_next_chain_key_returns_32_bytes(self) -> None:
        next_chain_key = derive_next_chain_key(make_chain_key(), 0)

        assert isinstance(next_chain_key, bytes)
        assert len(next_chain_key) == 32

    def test_derive_next_chain_key_is_deterministic_for_same_inputs(self) -> None:
        chain_key = make_chain_key()

        first = derive_next_chain_key(chain_key, 7)
        second = derive_next_chain_key(chain_key, 7)

        assert first == second

    def test_derive_next_chain_key_changes_with_counter(self) -> None:
        chain_key = make_chain_key()

        first = derive_next_chain_key(chain_key, 1)
        second = derive_next_chain_key(chain_key, 2)

        assert first != second

    @pytest.mark.parametrize(
        "bad_chain_key",
        [
            b"",
            b"x" * 31,
            b"x" * 33,
            "x" * 32,
            None,
        ],
    )
    def test_invalid_chain_key_raises_invalid_session_state_error(self, bad_chain_key) -> None:
        with pytest.raises(InvalidSessionStateError):
            derive_next_chain_key(bad_chain_key, 0)

    @pytest.mark.parametrize(
        "bad_counter",
        [
            -1,
            2 ** 64,
            "0",
            None,
            True,
            False,
        ],
    )
    def test_invalid_counter_raises_session_counter_error(self, bad_counter) -> None:
        with pytest.raises(SessionCounterError):
            derive_next_chain_key(make_chain_key(), bad_counter)


class TestAdvanceChain:
    def test_advance_chain_returns_message_key_next_chain_key_and_next_counter(self) -> None:
        chain_key = make_chain_key()

        message_key, next_chain_key, next_counter = advance_chain(chain_key, 0)

        assert isinstance(message_key, bytes)
        assert isinstance(next_chain_key, bytes)
        assert len(message_key) == 32
        assert len(next_chain_key) == 32
        assert next_counter == 1

    def test_advance_chain_message_key_and_next_chain_key_are_different(self) -> None:
        message_key, next_chain_key, _next_counter = advance_chain(make_chain_key(), 0)

        assert message_key != next_chain_key

    def test_advance_chain_matches_individual_derivations(self) -> None:
        chain_key = make_chain_key()
        counter = 9

        message_key, next_chain_key, next_counter = advance_chain(chain_key, counter)

        assert message_key == derive_message_key(chain_key, counter)
        assert next_chain_key == derive_next_chain_key(chain_key, counter)
        assert next_counter == counter + 1

    def test_advance_chain_changes_keys_for_different_counters(self) -> None:
        chain_key = make_chain_key()

        first_message_key, first_next_chain_key, first_next_counter = advance_chain(chain_key, 1)
        second_message_key, second_next_chain_key, second_next_counter = advance_chain(chain_key, 2)

        assert first_message_key != second_message_key
        assert first_next_chain_key != second_next_chain_key
        assert first_next_counter == 2
        assert second_next_counter == 3

    @pytest.mark.parametrize(
        "bad_chain_key",
        [
            b"",
            b"x" * 31,
            b"x" * 33,
            "x" * 32,
            None,
        ],
    )
    def test_invalid_chain_key_raises_invalid_session_state_error(self, bad_chain_key) -> None:
        with pytest.raises(InvalidSessionStateError):
            advance_chain(bad_chain_key, 0)

    @pytest.mark.parametrize(
        "bad_counter",
        [
            -1,
            2 ** 64,
            "0",
            None,
            True,
            False,
        ],
    )
    def test_invalid_counter_raises_session_counter_error(self, bad_counter) -> None:
        with pytest.raises(SessionCounterError):
            advance_chain(make_chain_key(), bad_counter)

    def test_advance_chain_counter_uint64_max_raises_session_counter_error(self) -> None:
        with pytest.raises(SessionCounterError):
            advance_chain(make_chain_key(), UINT64_MAX)
