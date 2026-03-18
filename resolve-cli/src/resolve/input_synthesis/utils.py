import shutil
from pathlib import Path


def require_file(path: Path, step: str) -> None:
    if not path.is_file():
        raise RuntimeError(f"{step} did not produce required file: {path}")


def prepare_output_path(output_path: Path, overwrite: bool) -> None:
    """Ensure output_path is ready for use: create parents, and fail or clear if it already exists."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        if not overwrite:
            raise RuntimeError(
                f"output_path already exists: {output_path}. "
                "Use --overwrite to replace it."
            )
        if output_path.is_dir():
            shutil.rmtree(output_path)
        else:
            output_path.unlink()
