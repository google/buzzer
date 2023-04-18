load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Go toolchain.
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "6b65cb7917b4d1709f9410ffe00ecf3e160edf674b78c54a894471320862184f",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.39.0/rules_go-v0.39.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.39.0/rules_go-v0.39.0.zip",
    ],
)
load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
go_rules_dependencies()
go_register_toolchains(version = "1.20.3")

# Porotobuf library.
http_archive(
    name = "rules_proto",
    sha256 = "dc3fb206a2cb3441b485eb1e423165b231235a1ea9b031b4433cf7bc1fa460dd",
    strip_prefix = "rules_proto-5.3.0-21.7",
    urls = [
        "https://github.com/bazelbuild/rules_proto/archive/refs/tags/5.3.0-21.7.tar.gz",
    ],
)
load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")
rules_proto_dependencies()
rules_proto_toolchains()

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
protobuf_deps()

# Absl
http_archive(
  name = "com_google_absl",
  urls = ["https://github.com/abseil/abseil-cpp/archive/refs/tags/20230125.2.zip"],
  sha256 = "2d40102022a01c6f3dddd23ec9ddafff49697a2e4bd09af68bccb74d26ecf64a",
  strip_prefix = "abseil-cpp-20230125.2",
)

# Protobuf source code.
http_archive(
    name = "com_google_protobuf",
    sha256 = "1ff680568f8e537bb4be9813bac0c1d87848d5be9d000ebe30f0bc2d7aabe045",
    strip_prefix = "protobuf-22.2",
    urls = [
		"https://github.com/protocolbuffers/protobuf/releases/download/v22.2/protobuf-22.2.tar.gz"
    ],
)

# Gazelle
http_archive(
    name = "bazel_gazelle",
    sha256 = "dfd6ee9d6b7aacf042c8d385177ebf459148cffb9d0b5b855aedd03234faafd7",
    strip_prefix = "bazel-gazelle-0.30.0",
    url = "https://github.com/bazelbuild/bazel-gazelle/archive/refs/tags/v0.30.0.zip",
)
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")
gazelle_dependencies()

load("@bazel_gazelle//:deps.bzl", "go_repository")
go_repository(
    name = "com_github_google_safehtml",
    build_file_proto_mode = "disable_global",
    importpath = "github.com/google/safehtml",
    sha256 = "394b34566cbe96a3758d2d2716377f0707f3448dbd9ccfc49ec5117e445ab36d",
    strip_prefix = "github.com/google/safehtml@v0.0.2",
    urls = [
        "https://storage.googleapis.com/cockroach-godeps/gomod/github.com/google/safehtml/com_github_google_safehtml-v0.0.2.zip",
    ],
)

go_repository(
    name = "com_github_golang_protobuf",
    build_file_proto_mode = "disable_global",
    importpath = "github.com/golang/protobuf",
    sha256 = "2dced4544ae5372281e20f1e48ca76368355a01b31353724718c4d6e3dcbb430",
    strip_prefix = "protobuf-1.5.3",
    urls = [
        "https://github.com/golang/protobuf/archive/refs/tags/v1.5.3.zip",
    ],
)
