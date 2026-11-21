//! SSI time formatting: `ngx_http_ssi_date_gmt_local_variable`.
//!
//! `$date_local` and `$date_gmt` are `strftime` output using the `timefmt` of the last
//! `<!--#config timefmt="…" -->`, defaulting to `%A, %d-%b-%Y %H:%M:%S %Z`. `%s` is handled
//! separately by nginx (epoch seconds without `strftime`), so it is handled separately here.

use std::time::{SystemTime, UNIX_EPOCH};

/// `ngx_http_ssi_timefmt`: `%A, %d-%b-%Y %H:%M:%S %Z`.
pub const DEFAULT_TIMEFMT: &str = "%A, %d-%b-%Y %H:%M:%S %Z";

const WEEKDAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// A broken-down UTC time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub weekday: u32,
    /// Day of the year, 0-based.
    pub year_day: u32,
}

impl Civil {
    /// Split `seconds` since the epoch into calendar fields (UTC).
    pub fn from_unix(seconds: i64) -> Self {
        let days = seconds.div_euclid(86_400);
        let of_day = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        // 1970-01-01 was a Thursday (4 in Sunday-based numbering).
        let weekday = (days + 4).rem_euclid(7) as u32;
        let year_day = (days - days_from_civil(year, 1, 1)) as u32;
        Self {
            year,
            month,
            day,
            hour: (of_day / 3600) as u32,
            minute: ((of_day % 3600) / 60) as u32,
            second: (of_day % 60) as u32,
            weekday,
            year_day,
        }
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// `strftime` with the conversions nginx pages actually use.
///
/// Unknown conversions are emitted literally (`%` followed by the character) instead of
/// failing, which keeps pages serving when a template has a typo.
pub fn strftime(format: &str, time: &Civil) -> String {
    let mut out = String::with_capacity(format.len() + 24);
    let chars: Vec<char> = format.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch != '%' {
            out.push(ch);
            index += 1;
            continue;
        }
        index += 1;
        let Some(conversion) = chars.get(index).copied() else {
            out.push('%');
            break;
        };
        index += 1;
        // `%E`/`%O` modifiers are ignored, like strftime does on glibc.
        let conversion = match conversion {
            'E' | 'O' => chars.get(index).copied().unwrap_or(conversion),
            other => other,
        };
        if conversion != '%' && matches!(conversion, 'E' | 'O') {
            // A modifier without a conversion character: keep it literal.
            out.push('%');
            out.push(conversion);
            continue;
        }
        if chars[index - 1] == 'E' || chars[index - 1] == 'O' {
            index += usize::from(index < chars.len());
        }
        match conversion {
            'a' => out.push_str(&WEEKDAYS[time.weekday as usize][..3]),
            'A' => out.push_str(WEEKDAYS[time.weekday as usize]),
            'b' | 'h' => out.push_str(&MONTHS[time.month as usize - 1][..3]),
            'B' => out.push_str(MONTHS[time.month as usize - 1]),
            'c' => out.push_str(&strftime("%a %b %e %H:%M:%S %Y", time)),
            'C' => out.push_str(&format!("{:02}", time.year.div_euclid(100))),
            'd' => out.push_str(&format!("{:02}", time.day)),
            'D' => out.push_str(&strftime("%m/%d/%y", time)),
            'e' => out.push_str(&format!("{:2}", time.day)),
            'F' => out.push_str(&strftime("%Y-%m-%d", time)),
            'H' => out.push_str(&format!("{:02}", time.hour)),
            'I' => out.push_str(&format!("{:02}", hour12(time.hour))),
            'j' => out.push_str(&format!("{:03}", time.year_day + 1)),
            'k' => out.push_str(&format!("{:2}", time.hour)),
            'l' => out.push_str(&format!("{:2}", hour12(time.hour))),
            'M' => out.push_str(&format!("{:02}", time.minute)),
            'm' => out.push_str(&format!("{:02}", time.month)),
            'n' => out.push('\n'),
            'p' => out.push_str(if time.hour < 12 { "AM" } else { "PM" }),
            'r' => out.push_str(&strftime("%I:%M:%S %p", time)),
            'R' => out.push_str(&strftime("%H:%M", time)),
            'S' => out.push_str(&format!("{:02}", time.second)),
            's' => out.push_str(&epoch_seconds(time).to_string()),
            'T' => out.push_str(&strftime("%H:%M:%S", time)),
            't' => out.push('\t'),
            'u' => out.push_str(&format!("{}", if time.weekday == 0 { 7 } else { time.weekday })),
            'w' => out.push_str(&format!("{}", time.weekday)),
            'x' => out.push_str(&strftime("%m/%d/%y", time)),
            'X' => out.push_str(&strftime("%H:%M:%S", time)),
            'y' => out.push_str(&format!("{:02}", time.year.rem_euclid(100))),
            'Y' => out.push_str(&time.year.to_string()),
            'Z' => out.push_str("UTC"),
            'z' => out.push_str("+0000"),
            '%' => out.push('%'),
            other => {
                out.push('%');
                out.push(other);
            }
        }
    }
    out
}

fn hour12(hour: u32) -> u32 {
    match hour % 12 {
        0 => 12,
        value => value,
    }
}

fn epoch_seconds(time: &Civil) -> i64 {
    days_from_civil(time.year, time.month, time.day) * 86_400
        + i64::from(time.hour) * 3600
        + i64::from(time.minute) * 60
        + i64::from(time.second)
}

/// Now, in UTC, with the format `timefmt` (`%s` handled by nginx without `strftime`).
pub fn now_formatted(format: &str) -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    if format == "%s" {
        return seconds.to_string();
    }
    strftime(format, &Civil::from_unix(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_round_trip() {
        let time = Civil::from_unix(0);
        assert_eq!((time.year, time.month, time.day), (1970, 1, 1));
        assert_eq!(time.weekday, 4, "1970-01-01 was a Thursday");
        let time = Civil::from_unix(1_700_000_000);
        assert_eq!((time.year, time.month, time.day), (2023, 11, 14));
        assert_eq!((time.hour, time.minute, time.second), (22, 13, 20));
    }

    #[test]
    fn default_format_matches_nginx() {
        let time = Civil::from_unix(0);
        assert_eq!(
            strftime(DEFAULT_TIMEFMT, &time),
            "Thursday, 01-Jan-1970 00:00:00 UTC"
        );
    }

    #[test]
    fn common_conversions() {
        let time = Civil::from_unix(1_700_000_000);
        assert_eq!(strftime("%Y-%m-%d %H:%M:%S", &time), "2023-11-14 22:13:20");
        assert_eq!(strftime("%a %b %e %j", &time), "Tue Nov 14 318");
        assert_eq!(strftime("%I:%M %p", &time), "10:13 PM");
        assert_eq!(strftime("%s", &time), "1700000000");
        assert_eq!(strftime("%u %w", &time), "2 2");
        assert_eq!(strftime("%q", &time), "%q");
        assert_eq!(strftime("%", &time), "%");
    }
}
