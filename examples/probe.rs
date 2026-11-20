fn expand_rendered(text: &str, path: &std::path::Path, files: &std::collections::HashMap<String, String>) -> String {
    println!("path={:?} keys={:?}", path, files.keys().collect::<Vec<_>>());
    String::new()
}
fn main() {
    let files = std::collections::HashMap::from([("\\\\?\\f:\\temp\\nginxrs\\conf\\nginxrs.conf".to_string(), "x".to_string())]);
    println!("hit={}", files.contains_key(&"\\\\?\\f:\\temp\\nginxrs\\conf\\nginxrs.conf".to_string()));
    let _ = expand_rendered;
}
