load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "hostsettings",
    srcs = [
        "hostsettings.go",
        "iosched.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/sentry/hostmm",
        "//runsc/config",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "hostsettings_test",
    size = "small",
    srcs = ["iosched_test.go"],
    library = ":hostsettings",
    deps = [
        "//runsc/config",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
