#!/usr/bin/env python3

from dataclasses import dataclass, field

from operator import attrgetter
import os
import csv
import json
import argparse
import subprocess
from pathlib import Path
from enum import Enum, auto
from typing import Any, Callable, Iterable, TypeVar

from univers.version_range import GenericVersionRange # type: ignore
from univers.versions import SemverVersion # type: ignore

class Reachability(Enum):
    UNKNOWN = auto()
    
    UNREACHABLE_NOT_FOUND = auto()
    UNREACHABLE_NO_PATH = auto()
    UNREACHABLE_NOT_VULNERABLE = auto()
    
    REACHABLE = auto()

@dataclass
class Sink:
    """
    Represent a target fn we would like to reach in a reachability
    query

    Preserves the info about a sink from vulnerabilities.json
    so we don't have to blindly assume we map 1-to-1 with an output
    reach query, since not every sink is reachable
    """

    # supplied by vulnerabilities.json   
    cve_id: str
    cve_description: str
    package_name: str
    vulnerable_package_version: str
    package_version: str | None
    cwe_id: str
    cwe_name: str
    affected_function: str
    affected_file: str

    @classmethod
    def from_vuln_dict(cls, vuln: dict[str, str]) -> "Sink":
        """
        Load metadata from TA2 supplied vulnerabilities.json
        """
        return cls(
            # The only required fields for our analysis
            cve_id=vuln["cve-id"],
            affected_function=vuln["affected-function"],

            # Misc
            cve_description=vuln["cve-description"],
            package_name=vuln["package-name"],
            vulnerable_package_version=vuln["package-version"],
            package_version=None, # populate later if we get the src dir
            cwe_id=vuln["cwe-id"],
            cwe_name=vuln["cwe-name"],
            affected_file=vuln["affected-file"],
        )

T = TypeVar("T")
K = TypeVar("K")
def group_by(items: Iterable[T], key_func: Callable[[T], K]):
    result: dict[K, list[T]] = {}
    for item in items:
        key = key_func(item)
        result.setdefault(key, []).append(item)
    
    return result

NodeID = str
EdgeID = str
NodeKind = str
EdgeKind = str

@dataclass
class Node:
    id: NodeID
    kind: NodeKind
    props: dict[str, Any] = field(default_factory=dict[str, Any])

    T = TypeVar('T')
    def get(self, key: str, default: T = None) -> str | T:
        return self.props.get(key, default)

    def __getitem__(self, key: str):
        return self.props[key]

    def __setitem__(self, key: str, value: Any):
        self.props[key] = value

    def get_name(self):
        if demangled_name := self.get("demangled_name", None):
            return demangled_name

        if name := self.get("name", None):
            return name

        if idx := self.get("idx", None):
            return idx
        
        return ""

    def __str__(self):
        return f"{self.kind}({self.get_name()}) ({self.id})"

@dataclass
class Nodes:
    def __init__(self, nodes: Iterable[Node] = []):
        self.ids = {node.id: node for node in nodes}
        self.kinds = group_by(nodes, attrgetter("kind"))

    ids: dict[NodeID, Node]
    kinds: dict[NodeKind, list[Node]]

    def __getitem__(self, id: NodeID):
        return self.ids[id]
    
    def __iter__(self):
        return self.ids.values().__iter__()

@dataclass
class Edge:
    id: EdgeID
    kind: EdgeKind
    src: NodeID
    dst: NodeID
    props: dict[str, Any] = field(default_factory=dict[str, Any])

    T = TypeVar('T')
    def get(self, key: str, default: T = None) -> str | T:
        return self.props.get(key, default)

    def __getitem__(self, key: str):
        return self.props[key]

    def __setitem__(self, key: str, value: Any):
        self.props[key] = value

@dataclass
class Edges:
    def __init__(self, edges: Iterable[Edge] = []):
        self.ids = {edge.id: edge for edge in edges}
        self.kinds = group_by(edges, attrgetter("kind"))
        self.pairs = group_by(edges, attrgetter("src", "dst"))
        self.srcs = group_by(edges, attrgetter("src"))
        self.dsts = group_by(edges, attrgetter("dst"))
        
    ids: dict[EdgeID, Edge]
    kinds: dict[EdgeKind, list[Edge]]
    pairs: dict[tuple[NodeID, NodeID], list[Edge]]
    srcs: dict[NodeID, list[Edge]]
    dsts: dict[NodeID, list[Edge]]

    def __getitem__(self, id: EdgeID):
        return self.ids[id]

    def __iter__(self):
        return self.ids.values().__iter__()

def demangle(names: Iterable[str]):
    name_input = "\n".join(names)
    res = subprocess.run(["c++filt"], input=name_input, stdout=subprocess.PIPE, text=True)
    if res.returncode:
        print(f"[RW]: ERROR: c++filt tool exited with code {res.returncode}")
        print("[RW]: c++filt STDOUT:", res.stdout)
        print("[RW]: c++filt STDERR:", res.stderr)
        return names

    return res.stdout.split("\n")

class FactParser:
    def __init__(self, facts_folder: Path):
        self.facts_folder = facts_folder
        # Load Nodes
        with (facts_folder / "nodes.facts").open() as f:
            self.nodes = Nodes([Node(id, kind) for id, kind in csv.reader(f)])
        with (facts_folder / "nodeprops.facts").open() as f:
            for id, key, value in csv.reader(f):
                self.nodes.ids[id].props[key] = value

        # Load Edges
        with (facts_folder / "edges.facts").open() as f:
            self.edges = Edges([Edge(id, kind, src, dst, props={}) for id, kind, src, dst in csv.reader(f)])
        with (facts_folder / "edgeprops.facts").open() as f:
            for id, key, value in csv.reader(f):
                self.edges[id].props[key] = value

    def demangle_names(self):
        with_names = [n for n in self.nodes if "name" in n.props]
        demangled = demangle([n["name"] for n in with_names])
        for n, demangled_name in zip(with_names, demangled):
            if n["name"] != demangled_name:
                n["demangled_name"] = demangled_name

    def get_func_id(self, func_name: str):
        # First try true symbol names
        for f in self.nodes.kinds["Function"]:
            if func_name in f["name"]:
                return f.id

        # Next try demangled C++ symbol names
        for f in self.nodes.kinds["Function"]:
            if func_name in f.props.get("demangled_name", ""):
                return f.id

@dataclass
class ReachToolResult:
    nodes: list[Node] = field(default_factory=list[Node])
    edges: list[str] = field(default_factory=list[str])

    def _as_cfg_path(self):
        nodes = iter(self.nodes)
        edges = iter(self.edges)
        try:
            yield str(next(nodes))
            while True:
                edge = next(edges)
                node = next(nodes)
                yield f"{edge} -> {node}"
        except StopIteration:
            return

    def as_cfg_path(self):
        return list(self._as_cfg_path())

    def _as_call_path(self):
        nodes = iter(self.nodes)
        edges = iter(self.edges)
        try:
            yield str(next(nodes))
            while True:
                edge = next(edges)
                node = next(nodes)
                if edge in ["Succ", "Contains"]:
                    continue
                yield f"{edge} -> {node}"
        except StopIteration:
            return

    def as_call_path(self):
        return list(self._as_call_path())

    def _as_edges(self):
        nodes = iter(self.nodes)
        edges = iter(self.edges)
        try:
            source = next(nodes)
            while True:
                edge = next(edges)
                destination = next(nodes)
                yield (source, edge, destination)
                source = destination
        except StopIteration:
            return

    def as_edges(self):
        return list(self._as_edges())

# A mapping from dst_id to path list
ReachToolResults = dict[str, list[ReachToolResult]]

@dataclass
class ReachabilityResult:
    sink: Sink
    reachability: Reachability = Reachability.UNKNOWN

    # found in nodeprops.facts
    func_id: str | None = None

    # from reach tool
    paths: list[ReachToolResult] | None = None

    def update_from_fact_parser(self, fact_parser: 'FactParser') -> None:
        """
        Looks for the function signature of a sink in nodeprops.facts
        and updates it with its func_id
        """
        func_id = fact_parser.get_func_id(self.sink.affected_function)

        if func_id:
            self.func_id = func_id
        else:
            self.reachability = Reachability.UNREACHABLE_NOT_FOUND

    def update_from_tool_results(self, tool_results: ReachToolResults):
        assert self.func_id is not None
        try:
            self.paths = tool_results[self.func_id]
        except KeyError:
            return

        self.reachability = Reachability.REACHABLE if len(self.paths) else Reachability.UNREACHABLE_NO_PATH

    def get_dict(self) -> dict[str, Any]:
        """
        Gets a dict of what we expect each sink to appear as
        in our output json to TA2
        """
        match self.reachability:
            case Reachability.UNREACHABLE_NOT_FOUND:
                classification = "unreachable"
                justification = {
                    "conclusion": "Not Found",
                    "reason": "The affected function was not found in compiled program metadata."
                }
            case Reachability.UNREACHABLE_NO_PATH:
                classification = "unreachable"
                justification = {
                    "conclusion": "Not Reachable",
                    "reason": "Control Flow Graph analysis found no paths to target function."
                }
            case Reachability.REACHABLE:
                assert self.paths
                classification = "potentially reachable"
                justification: dict[str, str | list[str]] = {
                    "conclusion": "Statically Reachable",
                    "reason": "Control Flow Graph analysis found the following candidate path...",
                    "call_path": self.paths[0].as_call_path(),
                    "control_flow_path": self.paths[0].as_cfg_path()
                }
            case Reachability.UNREACHABLE_NOT_VULNERABLE:
                classification = "unreachable"
                justification = {
                    "conclusion": "Not Vulnerable",
                    "reason": "The package version is not considered vulnerable according to the supplied version information. It may or may not still be reachable."
                }
            case other:
                print(f"[RW]: ERROR: Unexpected `reach` status \"{other}\"")
                classification = "Unable to assess"
                justification = {
                    "conclusion": "Error: internal tool failure"
                }

        return {
            "cve_id": self.sink.cve_id,
            "classification": classification,
            "justification": justification
        }

class ReachToolManager:
    def __init__(self, facts_dir: Path, src_id: str, tmp_reach_input_path: Path, reach_output_path: Path, reach_path: Path, reach_args: list[str]):
        self.facts_dir = facts_dir
        self.src_id = src_id
        self.reach_output_path = reach_output_path
        self.reach_path = reach_path
        self.reach_args = reach_args
        
        self.tmp_reach_input_path = tmp_reach_input_path
        self.tmp_reach_input_path.parent.mkdir(parents=True, exist_ok=True) # probably redundant
    
    def get_tool_input(self, results: list[ReachabilityResult]) -> dict[str, Any]:
        return {
            "cache": False,
            "queries": [
                {"src": self.src_id, "dst": result.func_id} for result in results
            ]
        }

    def serialize_tool_input(self, results: list[ReachabilityResult]) -> None:
        input = self.get_tool_input(results)

        with self.tmp_reach_input_path.open("w") as f:
            json.dump(input, f, indent=4)
            print(f"[RW]: Wrote {self.tmp_reach_input_path}")
    
    def invoke_reach(self) -> None:
        cmd = [
            str(self.reach_path),
            "-f", str(self.facts_dir),
            "-i", str(self.tmp_reach_input_path),
            "-o", str(self.reach_output_path)
        ]
        cmd.extend(self.reach_args)
        print(f"[RW]: Invoking reach '{' '.join(cmd)}'")
        res = subprocess.run(cmd, capture_output=True, text=True)

        if(res.returncode != 0):
            print(f"[RW]: ERROR: reach tool exited with code {res.returncode}")
            print("[RW]: reach STDOUT:", res.stdout)
            print("[RW]: reach STDERR:", res.stderr)
        else:
            print(f"[RW]: reach wrote output to {self.reach_output_path}")

    def get_tool_results(self, fact_parser: FactParser) -> ReachToolResults:
        with open(self.reach_output_path, "r") as rf:
            reach_file = json.load(rf)
            print(f"[RW]: Read {self.reach_output_path}")
        
        # Convert list of KV pairs to map
        def parse_result_path(nodes: list[str], edges: list[str]):
            return ReachToolResult(nodes=[fact_parser.nodes[id] for id in nodes], edges=edges)
                
        return {
            result["dst"]: [parse_result_path(**r) for r in result["paths"]] for result in reach_file["query_results"]
        }

class Orchestrator:
    def __init__(self, facts_dir: str, vuln_json_path: str, final_out_path: str, reach_bin_path: str|None, reach_args: list[str], cp_src_dir: str|None, graph_dir: str|None, entrypoint: str):
        default_reach_path = Path(__file__).absolute().parents[1] / "reach/build/reach"
        
        self.reach_args = reach_args
        self.facts_dir = Path(facts_dir)
        self.vuln_json_path = Path(vuln_json_path)
        self.final_out_path = Path(final_out_path)
        self.reach_bin_path = Path(reach_bin_path) if reach_bin_path else default_reach_path
        self.cp_src_dir = Path(cp_src_dir) if cp_src_dir else None

        self.fact_parser = FactParser(self.facts_dir)
        self.fact_parser.demangle_names()

        self.output_graph_path = graph_dir

        self.entrypoint = entrypoint

        # Load vulnerabilities.json
        with open(self.vuln_json_path, "r") as vj:
            vuln_json = json.load(vj)

        # Initialize results
        sinks = [Sink.from_vuln_dict(vuln) for vuln in vuln_json["vulnerabilities"]]
        self.results = [ReachabilityResult(sink) for sink in sinks]
        
    def parse_vulnerable_results(self):
        # If we have a source code directory, populate the package version
        if self.cp_src_dir is None:
            print("[RW]: WARNING: No source code directory provided, package versions will not be populated.")
            return
        cp_src_dir = self.cp_src_dir

        def is_vulnerable(vuln_version: str, actual_version: str) -> bool:
            vrange = GenericVersionRange.from_string(f"vers:generic/{vuln_version}")
            vstr = SemverVersion(actual_version)
            return vrange.contains(vstr)

        def get_version(package_name: str):
            # First, check for overlay ports
            vcpkg_json = cp_src_dir / "vcpkg-overlays/ports" / package_name / "vcpkg.json"
            
            # If no port, try root
            if not vcpkg_json.exists():
                vcpkg_json = cp_src_dir / "vcpkg.json"
            
            with vcpkg_json.open("r") as f:
                vcpkg_data = json.load(f)
            
            # Check that the name matches
            if vcpkg_data.get("name", None) != package_name:
                return None, vcpkg_json

            # get the version from the vcpkg.json
            return vcpkg_data.get("version", None), vcpkg_json

        # for sink in sinks:
        for result in self.results:
            name = result.sink.package_name
            vulnerable_version_string = result.sink.vulnerable_package_version

            vcpkg_version_string, vcpkg_json = get_version(name)
            if vcpkg_version_string is None:
                print(f"[RW]: WARNING: Could not find vcpkg.json for package '{name}' in {self.cp_src_dir / 'vcpkg-overlays/ports' / name}")
                continue

            print(f"[RW]: Populated package version for '{name}' from {vcpkg_json}: {vcpkg_version_string}")
            result.sink.package_version = vcpkg_version_string
            
            # check if there is a version match
            if is_vulnerable(vulnerable_version_string, vcpkg_version_string):
                print(f"[RW]: Package version '{vcpkg_version_string}' is considered vulnerable according to '{vulnerable_version_string}'")
            else:
                print(f"[RW]: Package version '{vcpkg_version_string}' is not considered vulnerable according to '{vulnerable_version_string}'")
                result.reachability = Reachability.UNREACHABLE_NOT_VULNERABLE

    def get_unsolved_results(self):
        return [result for result in self.results if result.reachability == Reachability.UNKNOWN]

    def parse_facts(self):
        "Update results from fact_parser to get func_id"
        for result in self.results:
            result.update_from_fact_parser(self.fact_parser)

    def run_reach_tool(self):
        "Run reach tool and update Results"
        # NOTE: we assume that we can always enter
        # the desired basic block from an 'fmain'
        src = self.fact_parser.get_func_id(self.entrypoint)
        assert src is not None, f"Could not find source function '{self.entrypoint}'"
        # TODO (optional): implement flags to specify the intermediate file placements

        """
        https://stackoverflow.com/a/48710609
        """
        def is_docker():
            def text_in_file(text: str, filename: str):
                try:
                    with open(filename, encoding='utf-8') as lines:
                        return any(text in line for line in lines)
                except OSError:
                    return False
            cgroup = '/proc/self/cgroup'
            return os.path.exists('/.dockerenv') or text_in_file('docker', cgroup)

        if os.getenv("CI") is not None or is_docker():
            tmp_in = Path("/tmp/reach_wrap_input.json")
            tmp_out = Path("/tmp/reach_wrap_output.json")
        else:
            tmp_in = Path("reach_wrap_input.json")
            tmp_out = Path("reach_wrap_output.json")

        self.input_manager = ReachToolManager(self.facts_dir, src, tmp_in, tmp_out, self.reach_bin_path, self.reach_args)
        
        unsolved_results = self.get_unsolved_results()
        self.input_manager.serialize_tool_input(unsolved_results)
        self.input_manager.invoke_reach()
        tool_results = self.input_manager.get_tool_results(fact_parser=self.fact_parser)
        for result in unsolved_results:
            result.update_from_tool_results(tool_results)

    def serialize_output(self):
        "Print results as final output"
        data = {
            "reachability_results": [result.get_dict() for result in self.results]
        }
        self.final_out_path.parent.mkdir(parents=True, exist_ok=True) # probably redundant
        with self.final_out_path.open("w") as f:
            json.dump(data, f, indent=4)
            print(f"[RW]: Wrote {self.final_out_path}.")
    
    def serialize_as_graph(self):
        if not self.output_graph_path:
            return
        
        os.makedirs(self.output_graph_path, exist_ok=True)

        # sink nodes
        with open(Path(self.output_graph_path, "nodeprops.facts"), "w") as nodeprops_file:
            for result in self.results:
                if result.reachability is Reachability.UNREACHABLE_NOT_FOUND:
                    continue

                nodeprops_file.write(f"{result.func_id},\"vulnerability_id\",{result.sink.cve_id}\n")
                nodeprops_file.write(f"{result.func_id},\"reachable\",{ True if result.reachability == Reachability.REACHABLE else False}\n")

        # Edges
        with (
            open(Path(self.output_graph_path, "edges.facts"), "w") as edges_file,
            open(Path(self.output_graph_path, "edgeprops.facts"), "w") as edgeprops_file,
            ):
            i = 0
            for result in self.results:
                if result.reachability is not Reachability.REACHABLE:
                    continue

                assert result.paths is not None
                for path in result.paths:
                    for source, edge, destination in path.as_edges():
                        edges_file.write(f"{i},{'ReachablePath'},{source.id},{destination.id}\n")
                        edgeprops_file.write(f"{i},{'kind'},{edge}\n")
                        i+=1

    def main(self):
        self.parse_vulnerable_results()
        self.parse_facts()

        self.run_reach_tool()
        self.serialize_output()
        self.serialize_as_graph()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Reach tool wrapper used to manipulate inputs and outputs to desired forms"
    )

    parser.add_argument(
        "-i",
        "--input",
        type=str,
        help="the vulnerabilities.json path",
        required=True
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="the path to write the output file to",
        required=True
    )

    parser.add_argument(
        "-f",
        "--facts",
        type=str,
        help="the folder containing the facts files",
        required=True
    )

    parser.add_argument(
        "-r",
        "--reach",
        type=str,
        help="the path to the reach binary",
        default=None
    )

    parser.add_argument(
        "-s",
        "--src",
        type=str,
        help="the folder containing the source code for the cp, it should have a vcpkg-overlays folder",
        default=None,
    )

    parser.add_argument(
        "-a",
        "--args",
        type=str,
        help="additional arguments passed verbatim to `reach`",
        nargs=argparse.REMAINDER,
        default=[]
    )

    parser.add_argument(
        "-g",
        "--graph",
        type=str,
        help="output a facts file in shared volume that can be imported into neo4j, this argument specifies the path",
        default=None,
        required=False
    )

    parser.add_argument(
        "-e",
        "--entry",
        type=str,
        help="The function to use as the entrypoint for reachability analysis. Defaults to `main`",
        default="main",
        required=False
    )

    args = parser.parse_args()
    # reach_out = Path("/tmp/reach_out.json")

    Orchestrator(args.facts, args.input, args.output, args.reach, args.args, args.src, args.graph, args.entry).main()
