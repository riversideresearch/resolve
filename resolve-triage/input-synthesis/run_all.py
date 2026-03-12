import argparse
import subprocess
from pathlib import Path

import improve_CVE
import reachability
import setup


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the full CVE analysis pipeline: setup, CVE improvement, reachability analysis, and input synthesis.",
        epilog="""Examples:
  python3 run_all.py claude cve.json out/
  python3 run_all.py codex cve.json out/""",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "agent",
        choices=("claude", "codex", "opencode"),
        help="Coding agent backend to execute prompts with.",
    )
    parser.add_argument(
        "cve_path",
        type=Path,
        help="Path to the input CVE file.",
    )
    parser.add_argument(
        "output_path",
        type=Path,
        help="Top-level output directory. Subdirectories are created for each phase.",
    )
    parser.add_argument(
        "--model",
        help="Optional model override passed through to the selected agent CLI.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite output subdirectories if they already exist.",
    )
    return parser.parse_args(argv)


def run(
    agent: str,
    cve_path: Path,
    output_path: Path,
    overwrite: bool,
    model: str | None = None,
) -> int:
    improve_cve_path = output_path / "improve_cve"
    reachability_path = output_path / "reachability"

    setup.run(agent=agent, cve_path=cve_path, model=model)

    improve_CVE.run(
        agent=agent,
        cve_path=cve_path,
        output_path=improve_cve_path,
        overwrite=overwrite,
        model=model,
    )

    reachability.run(
        agent=agent,
        cve_path=cve_path,
        improve_cve_path=improve_cve_path,
        output_path=reachability_path,
        overwrite=overwrite,
        model=model,
    )

    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run(
            agent=args.agent,
            cve_path=args.cve_path,
            output_path=args.output_path,
            overwrite=args.overwrite,
            model=args.model,
        )
    except subprocess.CalledProcessError as exc:
        print(f"agent failed with exit code {exc.returncode}")
        return exc.returncode if exc.returncode != 0 else 1
    except (RuntimeError, ValueError) as exc:
        print(exc)
        return -1


if __name__ == "__main__":
    raise SystemExit(main())
