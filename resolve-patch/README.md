# resolve-patch

`resolve-patch` allows patching in-the-wild binaries in-place via decompilation and recompilation with llvm patch files.

Setting the `"output"` key value in your `vulernabilities.json` to `"patch"` will produce a `resolve-patch.ll` file next to an un-instrumented binary.

Using `llvm-mctoll`, you can produce a dissassembled `{binary}-dis.ll` file like so:

```bash
llvm-mctoll -I "{YOUR_PATH_GOES_HERE}/mctoll-prototypes.h" {binary}
```

To reconcile the dissassembled program with the patch, and produce a new `.ll` file for recompilation, you can run the resolve patcher:

```bash
patcher.py -i {binary}-dis.ll -p resolve-patch.ll -o {binary}-patched.ll
```

With the patched `.ll`, simply recompile with `clang` like so:

```bash
clang {binary}-patched.ll -o {binary}-patched
```

## setup

see `./llvm-mctoll/README.md` for instructions on performing a in-tree build.

## limitations

llvm-mctoll cannot lift the following:
- sse/avx/neon (use `clange -mno-sse`)
- Windows/OSX binaries
- some C++ patterns (unclear)

llvm-mctoll requires prototypes for external/libc symbols to be passed to it with `-I` when lifting. Currently we must create this by hand, but I'm planning to introduce an automated tool. See `samples/mctoll-prototypes.h`.

See [llvm-mctoll current status](https://github.com/microsoft/llvm-mctoll/tree/master#current-status) for more information.

## patcher semantics

`patcher.py` is a text-based tool that tries to merge the resolve patch `.ll` with the mctoll dissassembled `.ll`.
While this produces `.ll` that can be recompiled without the need for CVEAssert, it also must try to reconcile semantics between each module, such as comdat, attributes, and metadata.

The current patcher must strip metadata annotations like `!dbg` and `!llvm.loop` patch functions before insertion.
It also treats top-level comdat declarations as merge items, tracking which ones already exist and append missing ones from the patch module.

Remaining edge cases include duplicate comdat names with different meanings, C++ templates/inline/vtables/RTTI creating many comdats, and attributes/linkage/visibility choices that are valid in resolve IR but awkward in the lifted IR.

<small>(these samples were produced by Codex 5.5 High, then hand-edited and verified)</small>
