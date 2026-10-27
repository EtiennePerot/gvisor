"""Stateify is a tool for generating state wrappers for Go types."""

def _go_stateify_impl(ctx):
    """Implementation for the stateify tool."""
    output = ctx.outputs.out

    # Run the stateify command.
    args = ["-output=%s" % output.path]
    args.append("-fullpkg=%s" % ctx.attr.package)
    if ctx.attr._statepkg:
        args.append("-statepkg=%s" % ctx.attr._statepkg)
    if ctx.attr.imports:
        args.append("-imports=%s" % ",".join(ctx.attr.imports))
    type_srcs = [f for f in ctx.files.type_srcs if f.extension == "go" and f not in ctx.files.srcs]
    if type_srcs:
        args.append("-typesrcs=%s" % ",".join([f.path for f in type_srcs]))
    args.append("--")
    for src in ctx.attr.srcs:
        args += [f.path for f in src.files.to_list()]
    ctx.actions.run(
        inputs = ctx.files.srcs + type_srcs,
        outputs = [output],
        mnemonic = "GoStateify",
        progress_message = "Generating state library %s" % ctx.label,
        arguments = args,
        executable = ctx.executable._tool,
    )

go_stateify = rule(
    implementation = _go_stateify_impl,
    doc = "Generates save and restore logic from a set of Go files.",
    attrs = {
        "srcs": attr.label_list(
            doc = """
The input source files. These files should include all structs in the package
that need to be saved.
""",
            mandatory = True,
            allow_files = True,
        ),
        "type_srcs": attr.label_list(
            doc = """
Other source files of the package, whose type declarations are used to
generate typed codecs for fields of types declared in them.
""",
            mandatory = False,
            allow_files = True,
        ),
        "imports": attr.string_list(
            doc = """
An optional list of extra non-aliased, Go-style absolute import paths required
for statified types.
""",
            mandatory = False,
        ),
        "package": attr.string(
            doc = "The fully qualified package name for the input sources.",
            mandatory = True,
        ),
        "out": attr.output(
            doc = "Name of the generator output file.",
            mandatory = True,
        ),
        "_tool": attr.label(
            executable = True,
            cfg = "exec",
            default = Label("//tools/go_stateify:stateify"),
        ),
        "_statepkg": attr.string(default = "gvisor.dev/gvisor/pkg/state"),
    },
)
