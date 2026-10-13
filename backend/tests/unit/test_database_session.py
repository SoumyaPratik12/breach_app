from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.database import Base, get_db
from app.models import User


def test_get_db_closes_session_after_use(monkeypatch):
    events = []

    class FakeSession:
        def close(self):
            events.append("close")

    fake_session = FakeSession()
    monkeypatch.setattr(
        "app.db.database.SessionLocal",
        lambda: fake_session,
    )
    generator = get_db()
    session = next(generator)

    assert session is fake_session

    try:
        next(generator)
    except StopIteration:
        pass

    assert events == ["close"]


def test_get_db_closes_session_when_request_raises(monkeypatch):
    events = []

    class FakeSession:
        def close(self):
            events.append("close")

    fake_session = FakeSession()
    monkeypatch.setattr(
        "app.db.database.SessionLocal",
        lambda: fake_session,
    )
    generator = get_db()
    next(generator)
    try:
        generator.throw(RuntimeError("simulated request failure"))
    except RuntimeError as exc:
        assert str(exc) == "simulated request failure"

    assert events == ["close"]


def test_uncommitted_changes_are_rolled_back_on_session_close():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine)
    session = TestingSessionLocal()

    try:
        user = User(
            email="rollback-test@example.com",
            password_hash="test-hash",
        )
        session.add(user)
        session.flush()
        user_id = user.id
        assert session.get(User, user_id) is not None

        session.close()
        with TestingSessionLocal() as verification_session:
            assert verification_session.get(User, user_id) is None
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
