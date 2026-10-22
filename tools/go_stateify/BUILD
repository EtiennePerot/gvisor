load("//tools:defs.bzl", "bzl_library", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "stateify",
    srcs = [
        "codec.go",
        "main.go",
    ],
    visibility = ["//:sandbox"],
    deps = ["//tools/constraintutil"],
)

go_test(
    name = "stateify_test",
    size = "small",
    srcs = [
        "codec.go",
        "codec_test.go",
        "main.go",
    ],
    deps = ["//tools/constraintutil"],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
)
