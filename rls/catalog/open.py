from patos import Singleton


class Open(Singleton):
    """Declaration for a table deliberately left without row level security."""

    def __repr__(self) -> str:
        return "rls.Open()"
