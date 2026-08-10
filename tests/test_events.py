"""Tests for the EventBus."""
import threading
from wifimonitor.events import EventBus, Events


def test_subscribe_and_emit():
    bus = EventBus()
    received = []
    bus.subscribe("test", lambda x: received.append(x))
    bus.emit("test", "hello")
    assert received == ["hello"]


def test_multiple_subscribers():
    bus = EventBus()
    a, b = [], []
    bus.subscribe("ev", lambda x: a.append(x))
    bus.subscribe("ev", lambda x: b.append(x))
    bus.emit("ev", 42)
    assert a == [42]
    assert b == [42]


def test_unsubscribe():
    bus = EventBus()
    received = []
    cb = lambda x: received.append(x)
    bus.subscribe("ev", cb)
    bus.unsubscribe("ev", cb)
    bus.emit("ev", "nope")
    assert received == []


def test_emit_no_subscribers():
    bus = EventBus()
    bus.emit("nonexistent", "data")  # Should not crash


def test_thread_safety():
    bus = EventBus()
    received = []
    bus.subscribe("ev", lambda x: received.append(x))
    threads = [threading.Thread(target=bus.emit, args=("ev", i)) for i in range(100)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(received) == 100


def test_clear():
    bus = EventBus()
    bus.subscribe("ev", lambda x: None)
    bus.clear()
    bus.emit("ev", "data")  # No crash, no subscribers


def test_events_constants():
    assert Events.ACCESS_POINT_DISCOVERED == "access_point_discovered"
    assert Events.HANDSHAKE_CAPTURED == "handshake_captured"
    assert Events.EVIL_TWIN_DETECTED == "evil_twin_detected"
