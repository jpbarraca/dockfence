"""Bridge interface naming for the container detail Networks table (display-only)."""

from dockfence.watcher import DockerWatcher


def test_bridge_iface_naming():
    # default bridge → docker0; host/none network modes → themselves
    assert DockerWatcher._bridge_iface("bridge", {}) == "docker0"
    assert DockerWatcher._bridge_iface("host", {}) == "host"
    assert DockerWatcher._bridge_iface("none", {}) == "none"
    # user-defined bridges take their NetworkID prefix
    net = {"NetworkID": "abcdef1234567890abcdef1234567890"}
    assert DockerWatcher._bridge_iface("mynet", net) == "br-abcdef123456"
    # missing/short NetworkID → empty (UI shows a dash)
    assert DockerWatcher._bridge_iface("mynet", {}) == ""
    assert DockerWatcher._bridge_iface("mynet", {"NetworkID": "short"}) == ""
