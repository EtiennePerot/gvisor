load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "bootapi",
    srcs = [
        "controller.go",
        "events.go",
        "fscheckpoint.go",
        "loader.go",
        "mount_hints.go",
        "network.go",
        "restore.go",
        "seccheck.go",
        "vfs.go",
    ],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/fsutil",
        "//pkg/log",
        "//pkg/sentry/checkpoint",
        "//pkg/sentry/fscheckpoint",
        "//pkg/sentry/seccheck",
        "//pkg/sentry/seccheck/sinks/null",
        "//pkg/sentry/seccheck/sinks/remote",
        "//pkg/state/statefile",
        "//pkg/urpc",
        "//runsc/config",
        "//runsc/specutils",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)

go_test(
    name = "bootapi_test",
    size = "small",
    srcs = ["mount_hints_test.go"],
    embed = [":bootapi"],
    deps = [
        "//runsc/config",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
