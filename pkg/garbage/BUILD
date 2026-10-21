load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "garbage",
    srcs = ["garbage.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/sync",
    ],
)

go_test(
    name = "garbage_test",
    size = "small",
    srcs = ["garbage_test.go"],
    library = ":garbage",
)
