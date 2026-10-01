use vcl_compiler::{compile, CompileOptions, IncludeResolver};

#[test]
fn every_shipped_vcl_policy_compiles() {
    for (name, source) in [
        ("default.vcl", include_str!("policies/default.vcl")),
        (
            "media_edge.vcl",
            include_str!("policies/media_edge.vcl"),
        ),
        (
            "controller/shop.vcl",
            include_str!("policies/controller/shop.vcl"),
        ),
        (
            "controller/api.vcl",
            include_str!("policies/controller/api.vcl"),
        ),
        (
            "controller/wildcard.vcl",
            include_str!("policies/controller/wildcard.vcl"),
        ),
        (
            "controller/not_found.vcl",
            include_str!("policies/controller/not_found.vcl"),
        ),
    ] {
        compile(source, CompileOptions::default())
            .unwrap_or_else(|error| panic!("{name} is outside the supported VCL surface: {error}"));
    }
}

#[test]
fn representative_vcl_4_0_policy_compiles_unchanged() {
    let source = r#"
vcl 4.0;
import std;

sub vcl_recv {
    if (req.http.Authorization || std.strstr(req.url, "/private")) {
        return (pass);
    }
    std.log({"carapace
compatibility corpus"});
    set req.http.X-Policy = {"carapace compatibility corpus"};
    return (hash);
}

sub vcl_backend_response {
    if (beresp.status >= 500) {
        return (abandon);
    }
    set beresp.ttl = 30s;
    return (deliver);
}

sub vcl_deliver {
    set resp.http.X-Cache = "edge";
    return (deliver);
}
"#;

    compile(source, CompileOptions::default()).expect("compile representative VCL 4.0 policy");
}

#[test]
fn controller_root_template_is_a_pinned_migration_guide() {
    let source = include_str!("policies/controller/upstream/root.vcl");
    let diagnostics = compile(source, CompileOptions::default()).unwrap_err();
    let messages = diagnostics
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        messages,
        [
            "unsupported VCL module 'file'",
            "unsupported VCL module 'accounting'",
            "backend declarations are not supported",
            "unsupported statement 'accounting.create_namespace'",
            "VCL objects are not supported",
            // `urlplus` and `headerplus` now parse, so their calls are no
            // longer rejected here. What the template still asks of them --
            // a `urlplus.write()` in `vcl_recv` and Varnish's workspace
            // rollback -- is refused by the type checker instead, which
            // `urlplus_and_headerplus_rejections_name_their_owner` pins.
            "unsupported statement 'accounting.set_namespace'",
            "unsupported statement 'accounting.add_keys'",
            "return (vcl(...)) is not supported",
        ]
    );
    assert!(diagnostics.diagnostics.iter().all(|diagnostic| {
        diagnostic
            .help
            .as_deref()
            .is_some_and(|help| !help.is_empty())
    }));

    let temporary = include_str!("policies/controller/upstream/temp_root.vcl");
    let temporary = compile(temporary, CompileOptions::default()).unwrap_err();
    assert_eq!(
        temporary
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.as_str())
            .collect::<Vec<_>>(),
        [
            "unsupported VCL module 'file'",
            "backend declarations are not supported",
            "VCL objects are not supported",
        ]
    );
}

/// What the Controller template asks of `urlplus` and `headerplus` that a
/// tenant cannot do, and what the diagnostic has to name.
///
/// These live apart from the template because the parser refuses that file
/// before the type checker ever sees a `vcl_recv` body: a rejection that
/// belongs to a later stage has to be provoked from a file that parses.
#[test]
fn urlplus_and_headerplus_rejections_name_their_owner() {
    let source = r#"
vcl 4.1;
import urlplus;
import headerplus;
sub vcl_recv {
    urlplus.url_delete_range(0, 0);
    urlplus.write();
    headerplus.init(req);
    headerplus.write_req0();
    return (hash);
}
"#;
    let diagnostics = compile(source, CompileOptions::default()).unwrap_err();
    let reported: Vec<(&str, &str)> = diagnostics
        .diagnostics
        .iter()
        .map(|diagnostic| {
            (
                diagnostic.message.as_str(),
                diagnostic.help.as_deref().unwrap_or_default(),
            )
        })
        .collect();

    // vcl_recv may rewrite the URL, as in Varnish, so only the workspace
    // rollback is refused.
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(
        reported[0].0,
        "unsupported headerplus function 'headerplus.write_req0'"
    );
    assert!(
        reported[0].1.starts_with("supported: "),
        "an unsupported function lists the ones that are: {}",
        reported[0].1
    );
}

/// Every Varnish variable a tenant cannot reach gets a line saying who owns
/// it instead. "unknown or unsupported VCL variable" on its own tells a
/// migrating author nothing, and they meet these one at a time.
#[test]
fn absent_variables_name_which_kind_of_absence_they_are() {
    for (variable, needle) in [
        ("req.backend_hint", "backends and directors belong"),
        ("bereq.backend", "backends and directors belong"),
        ("bereq.first_byte_timeout", "timeouts belong to the Varnish VCL"),
        ("req.storage", "storage selection belongs"),
        ("local.ip", "local socket address is not exposed"),
        ("server.ip", "server.hostname and server.identity are"),
        ("req.ttl", "set beresp.ttl"),
        ("client.port", "use client.ip"),
        ("req.hash", "hash_data() in vcl_hash"),
    ] {
        let source =
            format!("vcl 4.1; sub vcl_recv {{ set req.http.X = {variable}; return (hash); }}");
        let diagnostics = compile(&source, CompileOptions::default())
            .unwrap_err()
            .render("absent.vcl");
        assert!(
            diagnostics.contains(needle),
            "{variable} must be refused with {needle:?}:\n{diagnostics}"
        );
    }

    // The variables Varnish has and a tenant now reads.
    for (phase, variable) in [
        ("vcl_recv", "req.xid"),
        ("vcl_recv", "req.restarts"),
        ("vcl_recv", "server.hostname"),
        ("vcl_hit", "obj.hits"),
        ("vcl_deliver", "obj.uncacheable"),
        ("vcl_backend_fetch", "bereq.retries"),
    ] {
        let source = format!("vcl 4.1; sub {phase} {{ std.log({variable}); }}");
        let source = source.replace("vcl 4.1;", "vcl 4.1; import std;");
        compile(&source, CompileOptions::default())
            .unwrap_or_else(|error| panic!("{variable} in {phase}: {error}"));
    }

    // A client-side write from the backend side names the backend's copy.
    let source = "vcl 4.1; sub vcl_backend_fetch { set req.url = \"/x\"; }";
    let diagnostics = compile(source, CompileOptions::default())
        .unwrap_err()
        .render("absent.vcl");
    assert!(diagnostics.contains("bereq"), "{diagnostics}");
}

/// The Controller template's health include, pinned.
///
/// It is a *library* — no version marker — so it only reaches the compiler
/// through an `include`, which is why nothing compiled it before and its
/// verdicts drifted unpinned. `beresp.ttl = 0.1s` is truncated to whole
/// seconds with a warning rather than refused: `Cache-Control: max-age` is
/// `delta-seconds`, so `0.1s` can only ever mean `0s` here.
#[test]
fn the_controller_health_include_is_pinned() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/policies/controller/upstream");
    let main = "vcl 4.1;\n\
                include \"traffic_router_health.vcl\";\n\
                sub vcl_recv { return (traffic_router_health); }\n\
                sub vcl_backend_response { return (health_backend_response); }\n";

    let options = CompileOptions::default().with_include_resolver(directory(&root));
    let compiled = compile(main, options).expect("the include compiles");
    let warnings = compiled.warnings.render("traffic_router_health.vcl");
    assert!(
        warnings.contains("beresp.ttl is truncated to 0s"),
        "{warnings}"
    );
}

/// `sub vcl_synth` is a hook of its own: Varnish runs it after any
/// subroutine returns `synth(...)`, so the policy's copy runs there too,
/// against the real synthetic response, instead of being folded into the
/// hooks that dispatch it.
#[test]
fn vcl_synth_is_exported_as_its_own_hook() {
    let source = r#"
vcl 4.1;

sub vcl_recv {
    if (req.url ~ "^/deny") {
        return (synth(403, "denied"));
    }
    return (hash);
}

sub vcl_deliver {
    if (resp.status == 500) {
        return (synth(503, "origin is unwell"));
    }
    return (deliver);
}

sub vcl_synth {
    set resp.http.Content-Type = "text/plain";
    set resp.http.Retry-After = "30";
    synthetic("the page is unavailable");
    return (deliver);
}
"#;
    let compiled = compile(source, CompileOptions::default()).expect("a deliver synth compiles");
    for hook in ["on_recv", "on_deliver", "on_synth"] {
        assert!(compiled.exports.contains(hook), "{hook}");
    }

    let ir = vcl_compiler::dump_ir(source, CompileOptions::default()).expect("dump");
    let hooks = ir
        .split_once("== lowered (O0) ==")
        .expect("lowered section")
        .1
        .split("\n== ")
        .next()
        .expect("section body");
    let (dispatchers, synth) = hooks.split_once("fn on_synth").expect("vcl_synth is lowered");
    assert!(!dispatchers.contains("\"Retry-After\""), "{dispatchers}");
    assert!(synth.contains("\"Retry-After\""), "{synth}");
    assert!(synth.contains("synth_body"), "{synth}");
}

/// The custom-status redirect idiom: any subroutine that may return
/// `synth(...)` may name any three-digit status, and vcl_synth turns it into
/// the response.
#[test]
fn a_synth_redirect_compiles() {
    let source = r#"
vcl 4.1;
sub vcl_deliver {
    if (resp.status == 404) {
        return (synth(750, "/not-found"));
    }
}
sub vcl_synth {
    if (resp.status == 750) {
        set resp.http.Location = resp.reason;
        set resp.status = 302;
        set resp.reason = "Found";
        return (deliver);
    }
}
"#;
    compile(source, CompileOptions::default()).expect("the redirect idiom compiles");
}

/// A resolver that reads a test tree. The confinement the host applies lives
/// in `carapace::vcl_source`; `vcl-compiler` opens nothing itself, and the
/// compiler has already normalized the name it asks for.
fn directory(root: &std::path::Path) -> IncludeResolver {
    let root = root.to_path_buf();
    IncludeResolver::new(root.clone(), move |relative: &std::path::Path| {
        std::fs::read_to_string(root.join(relative)).map_err(|error| error.to_string())
    })
}
