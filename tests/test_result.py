"""Tests for lib/result.py - Result type for monadic error handling."""

import pytest

from iam_ra_cli.lib.result import (
    Err,
    Ok,
    err,
    flat_map,
    is_err,
    is_ok,
    map_err,
    map_ok,
    ok,
    unwrap,
    unwrap_err,
    unwrap_or,
)


class TestOkErr:
    """Tests for Ok and Err constructors."""

    def test_ok_holds_value(self) -> None:
        result = Ok(42)
        assert result.value == 42

    def test_err_holds_error(self) -> None:
        result = Err("something went wrong")
        assert result.error == "something went wrong"

    def test_ok_function(self) -> None:
        result = ok(42)
        assert isinstance(result, Ok)
        assert result.value == 42

    def test_err_function(self) -> None:
        result = err("oops")
        assert isinstance(result, Err)
        assert result.error == "oops"

    def test_ok_with_none_is_valid(self) -> None:
        result = Ok(None)
        assert result.value is None

    def test_ok_with_complex_type(self) -> None:
        data = {"key": [1, 2, 3]}
        result = Ok(data)
        assert result.value == data


class TestIsOkIsErr:
    """Tests for is_ok and is_err predicates."""

    def test_is_ok_with_ok(self) -> None:
        assert is_ok(Ok(1)) is True

    def test_is_ok_with_err(self) -> None:
        assert is_ok(Err("error")) is False

    def test_is_err_with_ok(self) -> None:
        assert is_err(Ok(1)) is False

    def test_is_err_with_err(self) -> None:
        assert is_err(Err("error")) is True


class TestMapOk:
    """Tests for map_ok combinator."""

    def test_map_ok_transforms_value(self) -> None:
        result = map_ok(Ok(5), lambda x: x * 2)
        assert isinstance(result, Ok)
        assert result.value == 10

    def test_map_ok_preserves_err(self) -> None:
        result = map_ok(Err("error"), lambda x: x * 2)
        assert isinstance(result, Err)
        assert result.error == "error"

    def test_map_ok_with_type_change(self) -> None:
        result = map_ok(Ok(42), str)
        assert isinstance(result, Ok)
        assert result.value == "42"


class TestMapErr:
    """Tests for map_err combinator."""

    def test_map_err_transforms_error(self) -> None:
        result = map_err(Err("error"), lambda e: f"wrapped: {e}")
        assert isinstance(result, Err)
        assert result.error == "wrapped: error"

    def test_map_err_preserves_ok(self) -> None:
        result = map_err(Ok(42), lambda e: f"wrapped: {e}")
        assert isinstance(result, Ok)
        assert result.value == 42


class TestFlatMap:
    """Tests for flat_map combinator (and_then/bind)."""

    def test_flat_map_chains_ok(self) -> None:
        def double_if_even(x: int) -> Ok[int] | Err[str]:
            if x % 2 == 0:
                return Ok(x * 2)
            return Err("not even")

        result = flat_map(Ok(4), double_if_even)
        assert isinstance(result, Ok)
        assert result.value == 8

    def test_flat_map_chains_to_err(self) -> None:
        def double_if_even(x: int) -> Ok[int] | Err[str]:
            if x % 2 == 0:
                return Ok(x * 2)
            return Err("not even")

        result = flat_map(Ok(3), double_if_even)
        assert isinstance(result, Err)
        assert result.error == "not even"

    def test_flat_map_short_circuits_on_err(self) -> None:
        called = False

        def should_not_be_called(x: int) -> Ok[int]:
            nonlocal called
            called = True
            return Ok(x)

        result = flat_map(Err("already failed"), should_not_be_called)
        assert isinstance(result, Err)
        assert result.error == "already failed"
        assert called is False


class TestUnwrap:
    """Tests for unwrap functions."""

    def test_unwrap_ok_returns_value(self) -> None:
        assert unwrap(Ok(42)) == 42

    def test_unwrap_err_raises(self) -> None:
        with pytest.raises(ValueError, match="Called unwrap on Err"):
            unwrap(Err("oops"))

    def test_unwrap_or_returns_value_on_ok(self) -> None:
        assert unwrap_or(Ok(42), 0) == 42

    def test_unwrap_or_returns_default_on_err(self) -> None:
        assert unwrap_or(Err("oops"), 0) == 0

    def test_unwrap_err_ok_raises(self) -> None:
        with pytest.raises(ValueError, match="Called unwrap_err on Ok"):
            unwrap_err(Ok(42))

    def test_unwrap_err_returns_error(self) -> None:
        assert unwrap_err(Err("oops")) == "oops"


class TestPatternMatching:
    """Tests for pattern matching usage (the primary way to use Result)."""

    def test_match_on_ok(self) -> None:
        result: Ok[int] | Err[str] = Ok(42)

        match result:
            case Ok(value):
                assert value == 42
            case Err(error):
                pytest.fail(f"Expected Ok, got Err: {error}")

    def test_match_on_err(self) -> None:
        result: Ok[int] | Err[str] = Err("failed")

        match result:
            case Ok(value):
                pytest.fail(f"Expected Err, got Ok: {value}")
            case Err(error):
                assert error == "failed"

    def test_chained_operations_with_match(self) -> None:
        """Demonstrate the recommended pattern for chaining operations."""

        def step1(x: int) -> Ok[int] | Err[str]:
            return Ok(x + 1)

        def step2(x: int) -> Ok[int] | Err[str]:
            return Ok(x * 2)

        def step3(x: int) -> Ok[int] | Err[str]:
            if x > 100:
                return Err("too big")
            return Ok(x)

        # Chain operations with match
        result: Ok[int] | Err[str]

        match step1(5):
            case Err() as e:
                result = e
            case Ok(v1):
                match step2(v1):
                    case Err() as e:
                        result = e
                    case Ok(v2):
                        result = step3(v2)

        # step1(5) = Ok(6), step2(6) = Ok(12), step3(12) = Ok(12)
        assert isinstance(result, Ok)
        assert result.value == 12

    def test_early_return_pattern(self) -> None:
        """Demonstrate early return pattern for error propagation."""

        def operation() -> Ok[int] | Err[str]:
            match Ok(5):
                case Err() as e:
                    return e
                case Ok(x):
                    pass

            match Ok(x * 2):
                case Err() as e:
                    return e
                case Ok(y):
                    pass

            return Ok(y + 1)

        result = operation()
        assert isinstance(result, Ok)
        assert result.value == 11
