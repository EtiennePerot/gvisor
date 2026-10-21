load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "hostsettings",
    srcs = [
        "cpufreq.go",
        "hostsettings.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/sentry/hostmm",
        "//runsc/config",
    ],
)

go_test(
    name = "hostsettings_test",
    size = "small",
    srcs = ["cpufreq_test.go"],
    library = ":hostsettings",
    deps = ["//runsc/config"],
)
