//! SSI template scanner shared by the renderer and its tests.

/// A literal template: static bytes that never change.
pub type Template = &'static [u8];

/// Whether `template` starts with an SSI directive marker.
pub fn starts_with_marker(template: Template) -> bool {
    template.starts_with(b"<!--#")
}

/// Split a template at the first directive marker, returning `(literal, rest)`.
pub fn split_marker(template: Template) -> (Template, Option<Template>) {
    match template
        .windows(5)
        .position(|window| window == b"<!--#")
    {
        Some(index) => (&template[..index], Some(&template[index..])),
        None => (template, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_split_keeps_literals() {
        let (literal, rest) = split_marker(b"abc<!--#echo var=\"uri\" -->");
        assert_eq!(literal, b"abc");
        assert_eq!(rest.unwrap(), b"<!--#echo var=\"uri\" -->");
        assert!(starts_with_marker(b"<!--#"));
        assert!(!starts_with_marker(b"<!-"));
        let (all, rest) = split_marker(b"no directive here");
        assert_eq!(all, b"no directive here");
        assert!(rest.is_none());
    }
}
