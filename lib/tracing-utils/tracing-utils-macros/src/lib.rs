use proc_macro::{Span, TokenStream};
use proc_macro_error::*;
use quote::ToTokens;
use syn::{
    parse_macro_input, parse_quote, Attribute, FnArg, ImplItem, ImplItemMethod, ItemImpl, Pat, Path,
};

/// Instruments all methods of a Tonic gRPC service with context propagation
/// through tracing_opentelemetry. Must be used before the async_trait attribute macro.
///
/// Specifically it will apply [`#[instrument]`] **to every method not already annotated with it**, and
/// it will pass it any options passed to this attribute. Note that this means that you can set options
/// in your `instrument_tonic_service` invocation, but you will need to specify them again in methods
/// you annotate manually with [`#[instrument]`] or [`#[tracing::instrument]`].
///
/// Accepts all the options from [`#[instrument]`].
///
/// [`#[tracing::instrument]`] is also recognized as an existing [`#[instrument]`] invocation.
///
/// [`#[instrument]`]: tracing_attributes::instrument
/// [`#[tracing::instrument]`]: tracing_attributes::instrument
#[proc_macro_error]
#[proc_macro_attribute]
pub fn instrument_tonic_service(args: TokenStream, item: TokenStream) -> TokenStream {
    let mut impl_block = parse_macro_input!(item as ItemImpl);

    for item in &mut impl_block.items {
        if let ImplItem::Method(method) = item {
            if method.sig.asyncness.is_none() {
                emit_error!(
                    method.sig, "Expected method to be async";
                    hint = Span::call_site() => "Make sure #[instrument_tonic_service] is applied **before** #[async-trait]";
                    hint = Span::call_site() => "#[instrument_tonic_service] can only be used with Tonic service impls";
                );
            }

            inject_trace_context_propagation_into_method(method);
            instrument_method(method, &args);
        }
    }

    impl_block.into_token_stream().into()
}

/// Injects a call to [tracing_utils::set_parent_ctx_from_tonic_request_metadata] at the start of
/// a method (that must receive the request as its first parameter).
fn inject_trace_context_propagation_into_method(method: &mut ImplItemMethod) {
    let req_arg = &method.sig.inputs[1];
    let req_arg_name = match req_arg {
        FnArg::Typed(arg) => match arg.pat.as_ref() {
            Pat::Ident(id) => id.ident.clone(),
            _ => {
                return emit_error!(
                    arg.pat, "Expected an identifier";
                    hint = Span::call_site() => "This macro can only be used with Tonic service impls (but honestly I think you wrote invalid Rust)";
                )
            }
        },
        _ => {
            return emit_error!(
                req_arg, "Expected typed function argument";
                hint = Span::call_site() => "This macro can only be used with Tonic service impls (but honestly I think you wrote invalid Rust)";
            )
        }
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

/// Create `#[instrument]` attribute with given arguments
fn gen_instrument_attr(args: TokenStream) -> Attribute {
    let mut instrument: Attribute = parse_quote!(#[tracing_utils::_macro_aux_tracing_instrument]);
    instrument.tokens = args.into();
    instrument
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
