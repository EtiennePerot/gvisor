load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "foreign",
    srcs = ["foreign.go"],
    stateify = False,
    visibility = ["//pkg/state/tests:__pkg__"],
)
