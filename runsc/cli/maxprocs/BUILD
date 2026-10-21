load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "maxprocs",
    srcs = ["maxprocs.go"],
    visibility = ["//runsc:__subpackages__"],
)

go_test(
    name = "maxprocs_test",
    size = "small",
    srcs = ["maxprocs_test.go"],
    embed = [":maxprocs"],
)
