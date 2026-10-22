load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "cbor",
    srcs = ["cbor.go"],
    importpath = "gvisor.dev/gvisor/runsc/cbor",
    visibility = ["//:sandbox"],
)

go_test(
    name = "cbor_test",
    size = "small",
    srcs = ["cbor_test.go"],
    library = ":cbor",
    deps = [
        "@com_github_fxamacker_cbor_v2//:go_default_library",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
