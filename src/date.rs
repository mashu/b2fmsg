//! UTC calendar conversions for the Winlink `Date:` header
//! (`YYYY/MM/DD HH:MM`), without pulling in a date library.

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `YYYY/MM/DD HH:MM` in UTC.
pub fn format(unix_secs: i64) -> String {
    let (y, m, d) = civil_from_days(unix_secs.div_euclid(86_400));
    let secs = unix_secs.rem_euclid(86_400);
    format!(
        "{y:04}/{m:02}/{d:02} {:02}:{:02}",
        secs / 3600,
        secs / 60 % 60
    )
}

/// Parses `YYYY/MM/DD HH:MM` (also `.` or `-` as date separators, as some
/// gateways send) into Unix seconds.
pub fn parse(text: &str) -> Option<i64> {
    let text = text.trim();
    let (date, time) = text.split_once(' ')?;
    let mut parts = date.split(['/', '.', '-']);
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    let (hh, mm) = time.trim().split_once(':')?;
    let hh: i64 = hh.parse().ok()?;
    let mm: i64 = mm.get(..2).unwrap_or(mm).parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 {
        return None;
    }
    Some(days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        assert_eq!(format(0), "1970/01/01 00:00");
        assert_eq!(format(951_782_400), "2000/02/29 00:00");
        assert_eq!(format(1_790_246_700), "2026/09/24 10:45");
        assert_eq!(parse("2026/09/24 10:45"), Some(1_790_246_700));
        assert_eq!(parse("2026.09.24 10:45"), Some(1_790_246_700));
        assert_eq!(parse("2026/13/24 10:45"), None);
        assert_eq!(parse("garbage"), None);
    }

    #[test]
    fn roundtrip_many() {
        for t in (0..4_000_000_000i64).step_by(7_777_777) {
            let minute = t - t % 60;
            assert_eq!(parse(&format(minute)), Some(minute));
        }
    }
}
