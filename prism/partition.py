from typing import (
    List, Callable, Iterable, TypeVar, Tuple, Dict, DefaultDict, Type,
    cast,
)
from collections import defaultdict

__all__ = (
    'partition',
    'copartition',
    'multipartition',
)


S = TypeVar('S')
T = TypeVar('T')


def partition(pred: Callable[[T], bool],
              it: Iterable[T],
              ) -> Tuple[List[T], List[T]]:
    ts: List[T] = []
    fs: List[T] = []
    t = ts.append
    f = fs.append
    for item in it:
        (t if pred(item) else f)(item)
    return fs, ts


def copartition(t: Type[S],
                it: Iterable[T],
                ) -> Tuple[List[T], List[S]]:
    return cast(
        Tuple[List[T], List[S]],
        partition(lambda x: isinstance(x, t), it),
    )


Tk = TypeVar('Tk')
Tv = TypeVar('Tv')


def multipartition(pred: Callable[[Tv], Tk],
                   it: Iterable[Tv],
                   ) -> Dict[Tk, Tuple[Tv, ...]]:
    a: DefaultDict[Tk, List[Tv]] = defaultdict(list)
    for item in it:
        a[pred(item)].append(item)

    return {k: tuple(v) for k, v in a.items()}
