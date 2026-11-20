use nginxrs::core::source;
fn main() {
    println!("{}", source::expand_include_path("F:\\temp\\site2\\conf\\mime.types", "f:\\temp\\site2\\conf\\mime.types").unwrap());
    println!("{}", source::expand_include_path("f:\\temp\\site2\\conf\\mime.types", "F:\\temp\\site2\\conf\\mime.types").unwrap());
}
