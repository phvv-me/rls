import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

import rls


def test_register_reads_a_plain_list_declared_before_registration() -> None:
    class Base(DeclarativeBase):
        pass

    class Item(Base):
        __tablename__ = "items"

        id: Mapped[int] = mapped_column(primary_key=True)

        __rls_policies__ = [
            rls.Policy(name="read", command=rls.Command.select, using=sa.column("id") == 1)
        ]

    rls.register(Base)

    policies = Base.metadata.info["rls_policies"]["items"]
    assert [policy.name for policy in policies] == ["read"]


def test_register_calls_a_callable_declared_after_registration() -> None:
    class Base(DeclarativeBase):
        pass

    rls.register(Base)

    class Item(Base):
        __tablename__ = "items"

        id: Mapped[int] = mapped_column(primary_key=True)
        owner_id: Mapped[int] = mapped_column()

        @classmethod
        def __rls_policies__(cls) -> list[rls.Policy]:
            return [
                rls.Policy(name="read", command=rls.Command.select, using=cls.owner_id == 1),
                rls.Policy(name="write", command=rls.Command.insert, check=cls.owner_id == 1),
            ]

    policies = Base.metadata.info["rls_policies"]["items"]
    assert [policy.name for policy in policies] == ["read", "write"]


def test_register_leaves_a_class_with_no_declared_policies_untouched() -> None:
    class Base(DeclarativeBase):
        pass

    rls.register(Base)

    class Plain(Base):
        __tablename__ = "plain"

        id: Mapped[int] = mapped_column(primary_key=True)

    assert "plain" not in Base.metadata.info["rls_policies"]


def test_register_stores_grant_role_on_the_metadata() -> None:
    class Base(DeclarativeBase):
        pass

    rls.register(Base, grant_role="app_role")
    assert Base.metadata.info["rls_grant_role"] == "app_role"


def test_two_registries_do_not_cross_register() -> None:
    """A class mapped on an unregistered base never gets an entry in a registered base's registry."""

    class Registered(DeclarativeBase):
        pass

    class Unregistered(DeclarativeBase):
        pass

    rls.register(Registered)

    class TrackedThing(Registered):
        __tablename__ = "tracked"

        id: Mapped[int] = mapped_column(primary_key=True)

        __rls_policies__ = [
            rls.Policy(name="read", command=rls.Command.select, using=sa.column("id") == 1)
        ]

    class UntrackedThing(Unregistered):
        __tablename__ = "untracked"

        id: Mapped[int] = mapped_column(primary_key=True)

        __rls_policies__ = [
            rls.Policy(name="read", command=rls.Command.select, using=sa.column("id") == 1)
        ]

    assert "tracked" in Registered.metadata.info["rls_policies"]
    assert "rls_policies" not in Unregistered.metadata.info
