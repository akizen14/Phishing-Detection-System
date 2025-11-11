"""Pytest configuration and fixtures."""
import pytest
from pathlib import Path


@pytest.fixture
def sample_html():
    """Fixture providing sample HTML."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Test Page</title>
        <script>console.log('test');</script>
        <style>.test { color: red; }</style>
    </head>
    <body>
        <div id="main" class="container">
            <h1>Title</h1>
            <p>Paragraph text</p>
        </div>
    </body>
    </html>
    """


@pytest.fixture
def sample_dom_bytes():
    """Fixture providing sample DOM bytes."""
    return b"html head body div span p"


@pytest.fixture
def temp_samples_dir(tmp_path):
    """Fixture providing temporary samples directory."""
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    return samples_dir
