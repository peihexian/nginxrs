//! The compiled `geoip_*` configuration and the field rules of every variable.
//!
//! This mirrors the data tables of `ngx_http_geoip_module.c`: the MaxMind DB paths
//! (`ngx_http_geoip_country_paths`, `…_city_paths`, `…_org_paths`) and the alpha-2 → alpha-3
//! conversion table libmaxminddb needs because it only stores alpha-2 codes.

use super::mmdb::{Lookup as Entry, Mmdb, Value};
use super::Lookup as Variable;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

/// Which directive opened a database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Country,
    City,
    Org,
}

/// One opened database (`gcf->country_mmdb` / `city_mmdb` / `org_mmdb`).
#[derive(Clone, Debug)]
pub struct Database {
    pub path: std::path::PathBuf,
    pub db: Arc<Mmdb>,
    /// `utf8` was requested (`ngx_http_geoip_charset`); MaxMind DB is always UTF-8.
    pub utf8: bool,
}

/// `ngx_http_geoip_conf_t` (main configuration).
#[derive(Clone, Debug, Default)]
pub struct Conf {
    pub country: Option<Database>,
    pub city: Option<Database>,
    pub org: Option<Database>,
    pub proxies: Vec<crate::core::geo::Cidr>,
    pub proxy_recursive: bool,
}

/// `ngx_http_geoip_open`: open a database and check that it is the right edition.
pub fn open(path: &Path, kind: Kind, charset: Option<&str>) -> Result<Database, String> {
    let utf8 = match charset {
        None => false,
        Some("utf8") => true,
        Some(other) => return Err(format!("invalid parameter \"{other}\"")),
    };
    let db = Mmdb::open(path).map_err(|error| format!("MMDB_open(\"{}\") failed: {error}", path.display()))?;
    let database_type = db.metadata().database_type.clone();
    let matches = match kind {
        Kind::Country => database_type.contains("Country"),
        Kind::City => database_type.contains("City"),
        Kind::Org => {
            database_type.contains("ASN")
                || database_type.contains("ISP")
                || database_type.contains("Org")
                || database_type.contains("Domain")
        }
    };
    if !matches {
        return Err(match kind {
            Kind::Country => format!(
                "invalid GeoIP Country database \"{}\" type:{}",
                path.display(),
                database_type
            ),
            Kind::City => format!(
                "invalid GeoIP City database \"{}\" type:{}",
                path.display(),
                database_type
            ),
            Kind::Org => format!(
                "invalid GeoIP database \"{}\" type:{}",
                path.display(),
                database_type
            ),
        });
    }
    Ok(Database {
        path: path.to_path_buf(),
        db: Arc::new(db),
        utf8,
    })
}

impl Conf {
    /// Store a database, refusing a second one for the same kind (`is duplicate`).
    pub fn set(&mut self, kind: Kind, database: Database) {
        let slot = match kind {
            Kind::Country => &mut self.country,
            Kind::City => &mut self.city,
            Kind::Org => &mut self.org,
        };
        if slot.is_some() {
            log::warn!(
                "geoip: {} is duplicate, keeping {}",
                database.path.display(),
                slot.as_ref().map(|db| db.path.display().to_string()).unwrap_or_default()
            );
            return;
        }
        *slot = Some(database);
    }

    /// The value of `variable` for `address`, or `None` when the lookup has no such field
    /// (`NGX_DECLINED`).
    pub fn value(&self, variable: Variable, address: IpAddr) -> Option<String> {
        match variable {
            Variable::Country(field) => {
                let database = self.country.as_ref()?;
                let entry = self.lookup(database, address)?;
                let value = string_of(database, &entry, &country_path(field))?;
                Some(match field {
                    CountryField::Code3 => convert_code3(&value),
                    _ => value,
                })
            }
            Variable::City(field) => {
                let database = self.city.as_ref()?;
                let entry = self.lookup(database, address)?;
                let path = city_path(field);
                match field {
                    CityField::Latitude | CityField::Longitude => {
                        let number = number_of(database, &entry, &path)?;
                        // `ngx_http_geoip_float`: coordinates are degrees; NaN fails here too.
                        if !(-180.0..=180.0).contains(&number) {
                            return None;
                        }
                        Some(render_float(number))
                    }
                    CityField::MetroCode | CityField::AreaCode => {
                        number_of(database, &entry, &path).map(|value| value.trunc().to_string())
                    }
                    CityField::CountryCode3 => {
                        let value = string_of(database, &entry, &city_path(CityField::CountryCode))?;
                        Some(convert_code3(&value))
                    }
                    _ => string_of(database, &entry, &path),
                }
            }
            Variable::Org => {
                let database = self.org.as_ref()?;
                let entry = self.lookup(database, address)?;
                // `ngx_http_geoip_org_paths`: ASNum, ISP, Org and Domain editions, in turn.
                for path in [
                    ["autonomous_system_organization"].as_slice(),
                    ["isp"].as_slice(),
                    ["organization"].as_slice(),
                    ["domain"].as_slice(),
                ] {
                    if let Some(value) = string_of(database, &entry, path) {
                        return Some(value);
                    }
                }
                None
            }
        }
    }

    fn lookup(&self, database: &Database, address: IpAddr) -> Option<super::mmdb::Lookup> {
        match database.db.lookup(address) {
            Ok(lookup) => lookup,
            Err(error) => {
                log::error!(
                    "MMDB_lookup_sockaddr() failed for {}: {error}",
                    database.path.display()
                );
                None
            }
        }
    }
}

/// `ngx_http_geoip_str`: a string field, `None` when absent or of another type.
fn string_of(database: &Database, entry: &Entry, path: &[&str]) -> Option<String> {
    match database.db.get(entry, path) {
        Ok(Some(Value::Text(text))) => Some(text),
        Ok(_) => None,
        Err(error) => {
            log::error!("MMDB_get_value failed for {}: {error}", database.path.display());
            None
        }
    }
}

/// `ngx_http_geoip_float` / `ngx_http_geoip_int`: a numeric field.
fn number_of(database: &Database, entry: &Entry, path: &[&str]) -> Option<f64> {
    match database.db.get(entry, path) {
        Ok(Some(value)) => value.as_f64().or_else(|| value.as_i64().map(|value| value as f64)),
        Ok(None) => None,
        Err(error) => {
            log::error!("MMDB_get_value failed for {}: {error}", database.path.display());
            None
        }
    }
}

fn country_path(field: CountryField) -> Vec<&'static str> {
    match field {
        CountryField::Code => vec!["country", "iso_code"],
        CountryField::Code3 => vec!["country", "iso_code"],
        CountryField::Name => vec!["country", "names", "en"],
    }
}

fn city_path(field: CityField) -> Vec<&'static str> {
    match field {
        CityField::ContinentCode => vec!["continent", "code"],
        CityField::CountryCode | CityField::CountryCode3 => vec!["country", "iso_code"],
        CityField::CountryName => vec!["country", "names", "en"],
        // libmaxminddb resolves an array index from the path, so `subdivisions.0.…` reads the
        // first entry (`ngx_http_geoip_path_region`).
        CityField::Region => vec!["subdivisions", "0", "iso_code"],
        CityField::RegionName => vec!["subdivisions", "0", "names", "en"],
        CityField::City => vec!["city", "names", "en"],
        CityField::PostalCode => vec!["postal", "code"],
        CityField::Latitude => vec!["location", "latitude"],
        CityField::Longitude => vec!["location", "longitude"],
        CityField::MetroCode => vec!["location", "metro_code"],
        CityField::AreaCode => vec!["location", "area_code"],
    }
}

/// Render a coordinate the way `ngx_sprintf("%f")` does (six decimals, trimmed like nginx's
/// `ngx_http_geoip_city_float_variable` which copies `GeoIPRecord`'s `%f` formatting).
fn render_float(value: f64) -> String {
    let mut text = format!("{value:.6}");
    if text.contains('.') {
        while text.ends_with('0') {
            text.pop();
        }
        if text.ends_with('.') {
            text.pop();
        }
    }
    text
}

/// `ngx_http_geoip_code3`: map an alpha-2 code to alpha-3; an unknown code is kept.
fn code3(code: &str) -> &str {
    COUNTRY_CODES
        .iter()
        .find(|(alpha2, _)| *alpha2 == code)
        .map(|(_, alpha3)| *alpha3)
        .unwrap_or(code)
}

/// The owned form used when building a variable value.
fn convert_code3(code: &str) -> String {
    code3(code).to_string()
}

/// The variables this module registers.
pub fn variables() -> Vec<(&'static str, &'static dyn crate::core::variables::VariableProvider)> {
    super::LOOKUPS
        .iter()
        .map(|(name, lookup)| {
            let provider: &'static dyn crate::core::variables::VariableProvider =
                Box::leak(Box::new(super::GeoipVariable { lookup: *lookup, name }));
            (*name, provider)
        })
        .collect()
}

/// Fields of `geoip_country*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountryField {
    Code,
    Code3,
    Name,
}

/// Fields of `geoip_city*` and the city part of the C offset table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CityField {
    ContinentCode,
    CountryCode,
    CountryCode3,
    CountryName,
    Region,
    RegionName,
    City,
    PostalCode,
    Latitude,
    Longitude,
    MetroCode,
    AreaCode,
}

/// `ngx_http_geoip_country_codes`: alpha-2 → alpha-3 for every ISO 3166-1 entry.
pub const COUNTRY_CODES: &[(&str, &str)] = &[
    ("AD", "AND"), ("AE", "ARE"), ("AF", "AFG"), ("AG", "ATG"), ("AI", "AIA"),
    ("AL", "ALB"), ("AM", "ARM"), ("AO", "AGO"), ("AQ", "ATA"), ("AR", "ARG"),
    ("AS", "ASM"), ("AT", "AUT"), ("AU", "AUS"), ("AW", "ABW"), ("AX", "ALA"),
    ("AZ", "AZE"), ("BA", "BIH"), ("BB", "BRB"), ("BD", "BGD"), ("BE", "BEL"),
    ("BF", "BFA"), ("BG", "BGR"), ("BH", "BHR"), ("BI", "BDI"), ("BJ", "BEN"),
    ("BL", "BLM"), ("BM", "BMU"), ("BN", "BRN"), ("BO", "BOL"), ("BQ", "BES"),
    ("BR", "BRA"), ("BS", "BHS"), ("BT", "BTN"), ("BV", "BVT"), ("BW", "BWA"),
    ("BY", "BLR"), ("BZ", "BLZ"), ("CA", "CAN"), ("CC", "CCK"), ("CD", "COD"),
    ("CF", "CAF"), ("CG", "COG"), ("CH", "CHE"), ("CI", "CIV"), ("CK", "COK"),
    ("CL", "CHL"), ("CM", "CMR"), ("CN", "CHN"), ("CO", "COL"), ("CR", "CRI"),
    ("CU", "CUB"), ("CV", "CPV"), ("CW", "CUW"), ("CX", "CXR"), ("CY", "CYP"),
    ("CZ", "CZE"), ("DE", "DEU"), ("DJ", "DJI"), ("DK", "DNK"), ("DM", "DMA"),
    ("DO", "DOM"), ("DZ", "DZA"), ("EC", "ECU"), ("EE", "EST"), ("EG", "EGY"),
    ("EH", "ESH"), ("ER", "ERI"), ("ES", "ESP"), ("ET", "ETH"), ("FI", "FIN"),
    ("FJ", "FJI"), ("FK", "FLK"), ("FM", "FSM"), ("FO", "FRO"), ("FR", "FRA"),
    ("GA", "GAB"), ("GB", "GBR"), ("GD", "GRD"), ("GE", "GEO"), ("GF", "GUF"),
    ("GG", "GGY"), ("GH", "GHA"), ("GI", "GIB"), ("GL", "GRL"), ("GM", "GMB"),
    ("GN", "GIN"), ("GP", "GLP"), ("GQ", "GNQ"), ("GR", "GRC"), ("GS", "SGS"),
    ("GT", "GTM"), ("GU", "GUM"), ("GW", "GNB"), ("GY", "GUY"), ("HK", "HKG"),
    ("HM", "HMD"), ("HN", "HND"), ("HR", "HRV"), ("HT", "HTI"), ("HU", "HUN"),
    ("ID", "IDN"), ("IE", "IRL"), ("IL", "ISR"), ("IM", "IMN"), ("IN", "IND"),
    ("IO", "IOT"), ("IQ", "IRQ"), ("IR", "IRN"), ("IS", "ISL"), ("IT", "ITA"),
    ("JE", "JEY"), ("JM", "JAM"), ("JO", "JOR"), ("JP", "JPN"), ("KE", "KEN"),
    ("KG", "KGZ"), ("KH", "KHM"), ("KI", "KIR"), ("KM", "COM"), ("KN", "KNA"),
    ("KP", "PRK"), ("KR", "KOR"), ("KW", "KWT"), ("KY", "CYM"), ("KZ", "KAZ"),
    ("LA", "LAO"), ("LB", "LBN"), ("LC", "LCA"), ("LI", "LIE"), ("LK", "LKA"),
    ("LR", "LBR"), ("LS", "LSO"), ("LT", "LTU"), ("LU", "LUX"), ("LV", "LVA"),
    ("LY", "LBY"), ("MA", "MAR"), ("MC", "MCO"), ("MD", "MDA"), ("ME", "MNE"),
    ("MF", "MAF"), ("MG", "MDG"), ("MH", "MHL"), ("MK", "MKD"), ("ML", "MLI"),
    ("MM", "MMR"), ("MN", "MNG"), ("MO", "MAC"), ("MP", "MNP"), ("MQ", "MTQ"),
    ("MR", "MRT"), ("MS", "MSR"), ("MT", "MLT"), ("MU", "MUS"), ("MV", "MDV"),
    ("MW", "MWI"), ("MX", "MEX"), ("MY", "MYS"), ("MZ", "MOZ"), ("NA", "NAM"),
    ("NC", "NCL"), ("NE", "NER"), ("NF", "NFK"), ("NG", "NGA"), ("NI", "NIC"),
    ("NL", "NLD"), ("NO", "NOR"), ("NP", "NPL"), ("NR", "NRU"), ("NU", "NIU"),
    ("NZ", "NZL"), ("OM", "OMN"), ("PA", "PAN"), ("PE", "PER"), ("PF", "PYF"),
    ("PG", "PNG"), ("PH", "PHL"), ("PK", "PAK"), ("PL", "POL"), ("PM", "SPM"),
    ("PN", "PCN"), ("PR", "PRI"), ("PS", "PSE"), ("PT", "PRT"), ("PW", "PLW"),
    ("PY", "PRY"), ("QA", "QAT"), ("RE", "REU"), ("RO", "ROU"), ("RS", "SRB"),
    ("RU", "RUS"), ("RW", "RWA"), ("SA", "SAU"), ("SB", "SLB"), ("SC", "SYC"),
    ("SD", "SDN"), ("SE", "SWE"), ("SG", "SGP"), ("SH", "SHN"), ("SI", "SVN"),
    ("SJ", "SJM"), ("SK", "SVK"), ("SL", "SLE"), ("SM", "SMR"), ("SN", "SEN"),
    ("SO", "SOM"), ("SR", "SUR"), ("SS", "SSD"), ("ST", "STP"), ("SV", "SLV"),
    ("SX", "SXM"), ("SY", "SYR"), ("SZ", "SWZ"), ("TC", "TCA"), ("TD", "TCD"),
    ("TF", "ATF"), ("TG", "TGO"), ("TH", "THA"), ("TJ", "TJK"), ("TK", "TKL"),
    ("TL", "TLS"), ("TM", "TKM"), ("TN", "TUN"), ("TO", "TON"), ("TR", "TUR"),
    ("TT", "TTO"), ("TV", "TUV"), ("TW", "TWN"), ("TZ", "TZA"), ("UA", "UKR"),
    ("UG", "UGA"), ("UM", "UMI"), ("US", "USA"), ("UY", "URY"), ("UZ", "UZB"),
    ("VA", "VAT"), ("VC", "VCT"), ("VE", "VEN"), ("VG", "VGB"), ("VI", "VIR"),
    ("VN", "VNM"), ("VU", "VUT"), ("WF", "WLF"), ("WS", "WSM"), ("YE", "YEM"),
    ("YT", "MYT"), ("ZA", "ZAF"), ("ZM", "ZMB"), ("ZW", "ZWE"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha2_maps_to_alpha3() {
        assert_eq!(code3("US"), "USA");
        assert_eq!(code3("CN"), "CHN");
        assert_eq!(code3("GB"), "GBR");
        // An unknown code is returned unchanged (declined by the C module, kept as is here).
        assert_eq!(code3("ZZ"), "ZZ");
    }

    #[test]
    fn coordinates_render_without_trailing_zeroes() {
        assert_eq!(render_float(45.5), "45.5");
        assert_eq!(render_float(-122.25), "-122.25");
        assert_eq!(render_float(0.0), "0");
        assert_eq!(render_float(37.7749), "37.7749");
    }

    #[test]
    fn path_tables_match_the_c_module() {
        assert_eq!(country_path(CountryField::Code), ["country", "iso_code"]);
        assert_eq!(city_path(CityField::City), ["city", "names", "en"]);
        assert_eq!(city_path(CityField::Region), ["subdivisions", "0", "iso_code"]);
        // `geoip_city_metro_code` reads `location.metro_code`; libmaxminddb-style
        // databases usually carry `metro_code` only in the City edition.
        assert_eq!(city_path(CityField::MetroCode), ["location", "metro_code"]);
        assert_eq!(city_path(CityField::Latitude), ["location", "latitude"]);
    }

    #[test]
    fn value_needs_a_database_and_an_entry() {
        let conf = Conf::default();
        assert_eq!(conf.value(Variable::Country(CountryField::Code), "127.0.0.1".parse().unwrap()), None);
    }
}
