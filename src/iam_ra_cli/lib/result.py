"""Result type for monadic error handling.

Inspired by Rust's Result<T, E>. Use pattern matching to handle results:

    match some_operation():
        case Ok(value):
            # handle success
        case Err(error):
            # handle error
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")
U = TypeVar("U")
E = TypeVar("E")


@dataclass(frozen=True, slots=True)
class Ok(Generic[T]):
    """Success case containing a value."""

    value: T


@dataclass(frozen=True, slots=True)
class Err(Generic[E]):
    """Error case containing an error."""

    error: E


# Type alias for Result
type Result[T, E] = Ok[T] | Err[E]


def ok(value: T) -> Ok[T]:
    """Create an Ok result."""
    return Ok(value)


def err(error: E) -> Err[E]:
    """Create an Err result."""
    return Err(error)


def is_ok(result: Result[T, E]) -> bool:
    """Check if result is Ok."""
    return isinstance(result, Ok)


def is_err(result: Result[T, E]) -> bool:
    """Check if result is Err."""
    return isinstance(result, Err)


def map_ok(result: Result[T, E], f: Callable[[T], U]) -> Result[U, E]:
    """Apply f to the value if Ok, otherwise return the Err unchanged."""
    match result:
        case Ok(value):
            return Ok(f(value))
        case Err() as e:
            return e


def map_err(result: Result[T, E], f: Callable[[E], U]) -> Result[T, U]:
    """Apply f to the error if Err, otherwise return the Ok unchanged."""
    match result:
        case Ok() as o:
            return o
        case Err(error):
            return Err(f(error))


def flat_map(result: Result[T, E], f: Callable[[T], Result[U, E]]) -> Result[U, E]:
    """Apply f to the value if Ok (f returns Result), otherwise return Err.

    Also known as `and_then` or `bind`.
    """
    match result:
        case Ok(value):
            return f(value)
        case Err() as e:
            return e


def unwrap(result: Result[T, E]) -> T:
    """Extract the value from Ok, or raise ValueError if Err.

    Use sparingly - prefer pattern matching.
    """
    match result:
        case Ok(value):
            return value
        case Err(error):
            raise ValueError(f"Called unwrap on Err: {error}")


def unwrap_or(result: Result[T, E], default: T) -> T:
    """Extract the value from Ok, or return default if Err."""
    match result:
        case Ok(value):
            return value
        case Err():
            return default


def unwrap_err(result: Result[T, E]) -> E:
    """Extract the error from Err, or raise ValueError if Ok.

    Use sparingly - prefer pattern matching.
    """
    match result:
        case Ok(value):
            raise ValueError(f"Called unwrap_err on Ok: {value}")
        case Err(error):
            return error
