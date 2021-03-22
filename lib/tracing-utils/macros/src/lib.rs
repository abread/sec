use proc_macro::TokenStream;
use quote::ToTokens;
use syn::{
    parse_macro_input, parse_quote, Attribute, FnArg, ImplItem, ImplItemMethod, ItemImpl, Pat,
    Path, Type,
};

/// Instruments all methods of a Tonic gRPC service with context propagation
/// through tracing_opentelemetry. Must be used before the async_trait attribute macro.
///
/// Specifically it will apply [`#[instrument]`] **to every method not already annotated with it**, and
/// it will pass it any options passed to this attribute. Note that this means that you can set options
/// in your `instrument_tonic_service` invocation, but you will need to specify them again in methods
/// you annotate manually with `#[instrument]` or `#[tracing::instrument]`.
///
/// Accepts all the options from [`#[instrument]`].
///
/// `#[tracing::instrument]` is also recognized as an existing `#[instrument]` invocations.
///
/// [`#[instrument]`]: https://docs.rs/tracing-attributes/0.1.15/tracing_attributes/attr.instrument.html
#[proc_macro_attribute]
pub fn instrument_tonic_service(args: TokenStream, item: TokenStream) -> TokenStream {
    let mut impl_block = parse_macro_input!(item as ItemImpl);

    for item in &mut impl_block.items {
        if let ImplItem::Method(method) = item {
            assert!(
                method.sig.asyncness.is_some(),
                "This macro must be applied **before** async-trait"
            );

            inject_trace_context_propagation_into_method(method);
            instrument_method(method, &args);
        }
    }

    impl_block.into_token_stream().into()
}

/// Injects a call to tracing_utils::set_parent_ctx_from_tonic_request_metadata at the start of
/// a method (that must receive the request as its first parameter).
fn inject_trace_context_propagation_into_method(method: &mut ImplItemMethod) {
    let req_arg_name = match &method.sig.inputs[1] {
        FnArg::Typed(arg) => {
            assert!(type_is_request(&arg.ty), "Method must take a request as the first argument after the receiver. Are you sure this is a Tonic service impl?");
            match arg.pat.as_ref() {
                Pat::Ident(id) => id.ident.clone(),
                _ => unreachable!("Request argument name should be an identifier. Are you sure this is a Tonic service impl? or valid Rust even?"),
            }
        },
        _ => unreachable!("Request argument should be a regular typed argument. Are you sure this is a Tonic service impl? or valid Rust even?"),
    };

    method.block.stmts.insert(
        0,
        parse_quote! {
            tracing_utils::set_parent_ctx_from_tonic_request_metadata(#req_arg_name.metadata());
        },
    );
}

/// Adds the `#[instrument]` attribute to a given method with the given arguments
/// if it does not exist already.
fn instrument_method(method: &mut ImplItemMethod, args: &TokenStream) {
    for attr in &method.attrs {
        if is_instrument_attr(attr) && !attr.tokens.is_empty() {
            return; // already annotated with #[instrument]
        }
    }

    let instr_attr = gen_instrument_attr(args.clone());
    method.attrs.push(instr_attr);
}

/// Create #[instrument] attribute with given arguments
fn gen_instrument_attr(args: TokenStream) -> Attribute {
    let mut instrument: Attribute = parse_quote!(#[tracing_utils::_macro_aux_tracing_instrument]);
    instrument.tokens = args.into();
    instrument
}

/// Check if provided type is tonic::Request or Request (does not look into the generic bits)
/// Use it to prevent accidental misusage (e.g. in a random impl)
fn type_is_request(mut ty: &Type) -> bool {
    // remove parenthesis
    while let Type::Paren(t) = ty {
        ty = &t.elem;
    }

    if let Type::Path(typath) = ty {
        let path = stringify_path_idents(&typath.path);

        (path.len() == 1 && path[0] == "Request")
            || (path.len() == 2 && path[0] == "tonic" && path[1] == "Request")
    } else {
        false
    }
}

/// Check if provided attribute is `#[instrument]` (possibly with arguments)
/// Recognizes tracing::instrument and instrument
fn is_instrument_attr(attr: &Attribute) -> bool {
    let path: Vec<String> = stringify_path_idents(&attr.path);

    (path.len() == 1 && path[0] == "instrument")
        || (path.len() == 2 && path[0] == "tracing" && path[1] == "instrument")
}

/// Get identifiers of a path as a Vec of Strings (retaining their order)
fn stringify_path_idents(path: &Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|s| {
            let mut s = s.clone();
            s.arguments = syn::PathArguments::None;

            s.into_token_stream().to_string()
        })
        .collect()
}
