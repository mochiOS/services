use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use viewkit::prelude::*;
use viewkit::view::{Constraints, MeasureContext, PaintContext};

const WEEKDAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

#[derive(Clone, Copy, Default)]
pub(crate) struct LoginClock;

impl View for LoginClock {
    fn measure(&self, constraints: Constraints, _context: &mut MeasureContext<'_>) -> Size {
        constraints.constrain(Size::new(520.0, 118.0))
    }

    fn paint(&self, bounds: Rect, context: &mut PaintContext<'_>) {
        let Some(clock) = ClockValue::now() else {
            return;
        };
        Text::new(clock.time)
            .font_size(64.0)
            .line_height(74.0)
            .weight(500)
            .alignment(TextAlignment::Center)
            .color(Color::WHITE)
            .paint(
                Rect::new(bounds.origin.x, bounds.origin.y, bounds.size.width, 74.0),
                context,
            );
        Text::new(clock.date)
            .font_size(18.0)
            .line_height(28.0)
            .weight(500)
            .alignment(TextAlignment::Center)
            .color(Color::rgba(255, 255, 255, 230))
            .paint(
                Rect::new(
                    bounds.origin.x,
                    bounds.origin.y + 76.0,
                    bounds.size.width,
                    28.0,
                ),
                context,
            );
        context.request_redraw_in_at(bounds, Instant::now() + clock.until_next_minute);
    }
}

struct ClockValue {
    time: String,
    date: String,
    until_next_minute: Duration,
}

impl ClockValue {
    fn now() -> Option<Self> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        let seconds = i64::try_from(elapsed.as_secs()).ok()?;
        let days = seconds.div_euclid(86_400);
        let seconds_in_day = seconds.rem_euclid(86_400);
        let hour = seconds_in_day / 3_600;
        let minute = (seconds_in_day % 3_600) / 60;
        let (year, month, day) = civil_date(days)?;
        let weekday = WEEKDAYS[(days + 4).rem_euclid(7) as usize];
        let remaining = 60 - (elapsed.as_secs() % 60);
        Some(Self {
            time: format!("{hour:02}:{minute:02}"),
            date: format!("{weekday}, {month:02}/{day:02}/{year:04}"),
            until_next_minute: Duration::from_secs(remaining.max(1)),
        })
    }
}

fn civil_date(days: i64) -> Option<(i64, i64, i64)> {
    let shifted = days.checked_add(719_468)?;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_phase = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_phase + 2) / 5 + 1;
    let month = month_phase + if month_phase < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Some((year, month, day))
}

#[cfg(test)]
mod tests {
    use super::civil_date;

    #[test]
    fn converts_unix_epoch_date() {
        assert_eq!(civil_date(0), Some((1970, 1, 1)));
    }

    #[test]
    fn converts_leap_day() {
        assert_eq!(civil_date(19_782), Some((2024, 2, 29)));
    }
}
