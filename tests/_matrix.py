"""Small deterministic unittest matrix helper."""

from __future__ import annotations


def add_matrix(cls, prefix, cases, body):
    """Add one unittest method per case with deterministic names."""
    for index, case in enumerate(cases):
        if not isinstance(case, tuple):
            case = (case,)

        def test(self, case=case):
            body(self, *case)

        test.__name__ = "test_{}_{:03d}".format(prefix, index)
        test.__qualname__ = "{}.{}".format(cls.__name__, test.__name__)
        setattr(cls, test.__name__, test)
    return cls
