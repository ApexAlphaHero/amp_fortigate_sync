import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from docker_inspector import DockerInspector


def _make_container(id_, name, image_tag, ports):
    c = MagicMock()
    c.id = id_
    c.name = name
    c.image.tags = [image_tag]
    c.image.short_id = "sha256:abc"
    c.ports = ports
    return c


@patch("docker_inspector.docker.DockerClient")
def test_get_running_containers_basic(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client

    container = _make_container(
        "abc123", "web", "nginx:latest",
        {"80/tcp": [{"HostPort": "8080"}]},
    )
    mock_client.containers.list.return_value = [container]

    inspector = DockerInspector()
    result = inspector.get_running_containers()

    assert len(result) == 1
    assert result[0]["name"] == "web"
    assert result[0]["ports"] == [{"host_port": 8080, "protocol": "tcp"}]


@patch("docker_inspector.docker.DockerClient")
def test_label_filter_passed_to_docker(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.containers.list.return_value = []

    inspector = DockerInspector(label_filter="amp-sync=true")
    inspector.get_running_containers()

    call_kwargs = mock_client.containers.list.call_args[1]
    assert call_kwargs["filters"]["label"] == "amp-sync=true"


@patch("docker_inspector.docker.DockerClient")
def test_no_label_filter_when_blank(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.containers.list.return_value = []

    inspector = DockerInspector(label_filter="")
    inspector.get_running_containers()

    call_kwargs = mock_client.containers.list.call_args[1]
    assert "label" not in call_kwargs["filters"]


@patch("docker_inspector.docker.DockerClient")
def test_container_with_no_ports(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client

    container = _make_container("x1", "worker", "python:3.11", {})
    mock_client.containers.list.return_value = [container]

    inspector = DockerInspector()
    result = inspector.get_running_containers()

    assert result[0]["ports"] == []


@patch("docker_inspector.docker.DockerClient")
def test_docker_error_returns_empty(mock_client_cls):
    import docker.errors
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.containers.list.side_effect = docker.errors.DockerException("boom")

    inspector = DockerInspector()
    assert inspector.get_running_containers() == []
