//! gql-parser — high-performance GraphQL query parser for firewall analysis.

use async_graphql_parser::parse_query;
use async_graphql_parser::types::*;
use serde::Serialize;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use tiny_http::{Header, Response, Server};

static REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Serialize)]
struct QueryInfo {
    operation_type: String,
    operation_name: Option<String>,
    depth: usize,
    field_count: usize,
    field_paths: Vec<String>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--listen" {
        let port = args.get(2).cloned().unwrap_or("9090".to_string());
        run_http_sidecar(&port);
    } else if args.len() > 1 {
        let path = PathBuf::from(&args[1]);
        let query = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("error reading file {}: {}", path.display(), e);
            std::process::exit(1);
        });
        match analyze_query(&query) {
            Ok(info) => println!("{}", serde_json::to_string_pretty(&info).unwrap()),
            Err(e) => {
                eprintln!("parse error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        let mut query = String::new();
        std::io::stdin()
            .read_to_string(&mut query)
            .expect("failed to read from stdin");
        match analyze_query(&query.trim()) {
            Ok(info) => println!("{}", serde_json::to_string_pretty(&info).unwrap()),
            Err(e) => {
                eprintln!("parse error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn run_http_sidecar(port: &str) {
    let addr = format!("0.0.0.0:{}", port);
    let server = Server::http(&addr).unwrap_or_else(|e| {
        eprintln!("failed to start HTTP server: {}", e);
        std::process::exit(1);
    });
    eprintln!("gql-parser HTTP sidecar listening on {}", addr);

    let json_hdr = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    let cors_hdr = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap();

    for mut request in server.incoming_requests() {
        let count = REQUEST_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
        let mut body = String::new();
        if request.as_reader().read_to_string(&mut body).is_err() {
            let _ = request.respond(
                Response::from_string(r#"{"error":"cannot read body"}"#)
                    .with_status_code(400).with_header(json_hdr.clone()).with_header(cors_hdr.clone()),
            );
            continue;
        }
        let q = match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(v) => v.get("query").and_then(|s| s.as_str().map(String::from)),
            Err(_) => None,
        };
        let query_str = match q {
            Some(s) => s,
            None => {
                let _ = request.respond(
                    Response::from_string(r#"{"error":"missing 'query' field"}"#)
                        .with_status_code(400).with_header(json_hdr.clone()).with_header(cors_hdr.clone()),
                );
                continue;
            }
        };
        match analyze_query(&query_str) {
            Ok(info) => {
                let json = serde_json::to_string(&info).unwrap();
                let _ = request.respond(
                    Response::from_string(json).with_status_code(200)
                        .with_header(json_hdr.clone()).with_header(cors_hdr.clone()),
                );
            }
            Err(e) => {
                let err = serde_json::json!({"error": format!("{}", e)});
                let _ = request.respond(
                    Response::from_string(err.to_string()).with_status_code(400)
                        .with_header(json_hdr.clone()).with_header(cors_hdr.clone()),
                );
            }
        }
        if count % 1000 == 0 {
            eprintln!("gql-parser: processed {} requests", count);
        }
    }
}

fn analyze_query(query: &str) -> Result<QueryInfo, String> {
    if query.trim().is_empty() {
        return Err("empty query".to_string());
    }
    let doc = parse_query(query).map_err(|e| format!("parse error: {}", e))?;

    let mut operation_type = "query".to_string();
    let mut operation_name: Option<String> = None;
    let mut depth: usize = 0;
    let mut field_count: usize = 0;
    let mut field_paths: Vec<String> = Vec::new();

    // doc.operations provides an iterator over OperationDefinition
    for op in doc.operations.iter() {
        let (op_name, def_pos) = op;
        let def = &def_pos.node;
        operation_type = match def.ty {
            OperationType::Query => "query",
            OperationType::Mutation => "mutation",
            OperationType::Subscription => "subscription",
        }.to_string();
        if let Some(ref name_val) = op_name {
            operation_name = Some(name_val.to_string());
        }

        let mut stack: Vec<(&SelectionSet, String, usize)> = Vec::new();
        stack.push((&def.selection_set.node, String::new(), 0));

        while let Some((sel_set, prefix, cdepth)) = stack.pop() {
            for selection in &sel_set.items {
                let sel = &selection.node;
                match sel {
                    Selection::Field(f) => {
                        field_count += 1;
                        let name = f.node.name.node.to_string();
                        let path = if prefix.is_empty() { name.clone() } else { format!("{}.{}", prefix, name) };
                        field_paths.push(path.clone());
                        let nd = cdepth + 1;
                        if nd > depth { depth = nd; }
                        // Push sub-selections onto stack for DFS
                        if !f.node.selection_set.node.items.is_empty() {
                            stack.push((&f.node.selection_set.node, path, nd));
                        }
                    }
                    Selection::FragmentSpread(sp) => {
                        let frag_name = &sp.node.fragment_name.node;
                        // Look up fragment in doc
                        if let Some(frag) = doc.fragments.get(frag_name) {
                            let frag_sel = &frag.node.selection_set.node;
                            if !frag_sel.items.is_empty() {
                                stack.push((frag_sel, prefix.clone(), cdepth));
                            }
                        }
                    }
                    Selection::InlineFragment(inl) => {
                        let inl_sel = &inl.node.selection_set.node;
                        if !inl_sel.items.is_empty() {
                            stack.push((inl_sel, prefix.clone(), cdepth));
                        }
                    }
                }
            }
        }
    }

    Ok(QueryInfo { operation_type, operation_name, depth, field_count, field_paths })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple() { let r = analyze_query("{ hello }").unwrap(); assert_eq!(r.depth, 1); assert_eq!(r.field_count, 1); }
    #[test]
    fn test_nested() { let r = analyze_query("{ a { b } }").unwrap(); assert_eq!(r.depth, 2); assert_eq!(r.field_count, 2); }
    #[test]
    fn test_deep() { let r = analyze_query("{ a { b { c { d } } } }").unwrap(); assert_eq!(r.depth, 4); assert_eq!(r.field_count, 4); }
    #[test]
    fn test_mutation() { let r = analyze_query("mutation M { create { id } }").unwrap(); assert_eq!(r.operation_type, "mutation"); }
    #[test]
    fn test_named() { let r = analyze_query("query Q { x }").unwrap(); assert_eq!(r.operation_name, Some("Q".to_string())); }
    #[test]
    fn test_invalid() { assert!(analyze_query("{ bad !!! }").is_err()); assert!(analyze_query("").is_err()); }
    #[test]
    fn test_paths() { let r = analyze_query("{ u { p { e } } }").unwrap(); assert!(r.field_paths.contains(&"u.p.e".to_string())); }
}
