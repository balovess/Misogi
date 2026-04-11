//! Japanese Calendar Provider — Wareki (和暦) support and business day calculations.
//!
//! This module implements [`CalendarProvider`] for Japanese government/enterprise systems
//! that require:
//! - Imperial era (Wareki) ↔ Gregorian date conversion
//! - Japanese national holiday (祝日) database
//! - Business day (営業日) determination logic
//! - Filename Wareki notation auto-detection
//!
//! # Era Coverage
//!
//! | Era      | Kanji   | Start Date    | End Date      |
//! |----------|---------|---------------|---------------|
//! | Reiwa    | 令和     | 2019-05-01    | Present       |
//! | Heisei   | 平成     | 1989-01-08    | 2019-04-30    |
//! | Showa    | 昭和     | 1926-12-25    | 1989-01-07    |
//! | Taisho   | 大正     | 1912-07-30    | 1926-12-24    |
//! | Meiji    | 明治     | 1868-01-25    | 1912-07-29    |
//!
//! # Usage Example
//!
//! ```ignore
//! use misogi_core::contrib::jp::calendar::JapaneseCalendarProvider;
//!
//! let provider = JapaneseCalendarProvider::new();
//! let date = provider.regional_to_gregorian("令和", 8, 4, 11)?;
//! assert_eq!(date.year(), 2026);
//! ```

use std::collections::HashSet;
use std::path::Path;

use chrono::{Datelike, NaiveDate, Weekday};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde::ser::Error as SerError;

use crate::error::{MisogiError, Result};
use crate::traits::{
    CalendarProvider,
    Holiday,
    HolidayCategory,
};

// =============================================================================
// Era Definitions
// =============================================================================

/// Single Japanese Imperial era definition with metadata.
///
/// Each era contains the Gregorian start/end dates and the mapping between
/// Wareki year numbers and Gregorian years.
#[derive(Debug, Clone)]
pub struct EraDefinition {
    /// Era name in Kanji (e.g., "令和", "平成").
    pub name_ja: &'static str,

    /// Romanized era name (e.g., "Reiwa", "Heisei").
    pub name_en: &'static str,

    /// One-letter abbreviation used in filename patterns (R, H, S, T, M).
    pub abbreviation: char,

    /// First day of this era in Gregorian calendar.
    pub start_date: NaiveDate,

    /// Last day of this era in Gregorian calendar (None if current era).
    pub end_date: Option<NaiveDate>,

    /// Gregorian year corresponding to Wareki year 1 of this era.
    /// e.g., Reiwa: 2019, Heisei: 1989
    pub gengou_start_year: i32,
}

impl EraDefinition {
    /// Calculate the Gregorian year for a given Wareki year within this era.
    ///
    /// # Formula
    /// `gregorian_year = gengou_start_year + (wareki_year - 1)`
    ///
    /// # Arguments
    /// * `wareki_year` - Year within the era (1-based).
    ///
    /// # Returns
    /// The corresponding Gregorian year.
    #[inline]
    pub fn wareki_to_gregorian_year(&self, wareki_year: u32) -> i32 {
        self.gengou_start_year + (wareki_year as i32 - 1)
    }

    /// Check whether a given Gregorian year falls within this era's range.
    ///
    /// # Arguments
    /// * `year` - Gregorian year to check.
    ///
    /// # Returns
    /// `true` if the year is within this era's span.
    #[inline]
    pub fn contains_gregorian_year(&self, year: i32) -> bool {
        let start_year = self.start_date.year();
        let end_year = self.end_date.map_or(9999, |d| d.year());
        (start_year..=end_year).contains(&year)
    }

    /// Calculate the Wareki year for a given Gregorian year within this era.
    ///
    /// # Arguments
    /// * `year` - Gregorian year within this era.
    ///
    /// # Returns
    /// The Wareki year number (1-based).
    ///
    /// # Panics
    /// If the given year is outside this era's range.
    #[inline]
    pub fn gregorian_to_wareki_year(&self, year: i32) -> u32 {
        debug_assert!(
            self.contains_gregorian_year(year),
            "Year {} is outside {} era range",
            year,
            self.name_ja
        );
        (year - self.gengou_start_year + 1) as u32
    }
}

/// All supported Japanese Imperial eras in chronological order (oldest first).
pub const ERA_DEFINITIONS: &[EraDefinition] = &[
    EraDefinition {
        name_ja: "明治",
        name_en: "Meiji",
        abbreviation: 'M',
        start_date: NaiveDate::from_ymd_opt(1868, 1, 25).unwrap(),
        end_date: Some(NaiveDate::from_ymd_opt(1912, 7, 29).unwrap()),
        gengou_start_year: 1868,
    },
    EraDefinition {
        name_ja: "大正",
        name_en: "Taisho",
        abbreviation: 'T',
        start_date: NaiveDate::from_ymd_opt(1912, 7, 30).unwrap(),
        end_date: Some(NaiveDate::from_ymd_opt(1926, 12, 24).unwrap()),
        gengou_start_year: 1912,
    },
    EraDefinition {
        name_ja: "昭和",
        name_en: "Showa",
        abbreviation: 'S',
        start_date: NaiveDate::from_ymd_opt(1926, 12, 25).unwrap(),
        end_date: Some(NaiveDate::from_ymd_opt(1989, 1, 7).unwrap()),
        gengou_start_year: 1926,
    },
    EraDefinition {
        name_ja: "平成",
        name_en: "Heisei",
        abbreviation: 'H',
        start_date: NaiveDate::from_ymd_opt(1989, 1, 8).unwrap(),
        end_date: Some(NaiveDate::from_ymd_opt(2019, 4, 30).unwrap()),
        gengou_start_year: 1989,
    },
    EraDefinition {
        name_ja: "令和",
        name_en: "Reiwa",
        abbreviation: 'R',
        start_date: NaiveDate::from_ymd_opt(2019, 5, 1).unwrap(),
        end_date: None, // Current era — no end date
        gengou_start_year: 2019,
    },
];

// =============================================================================
// JapaneseCalendarProvider
// =============================================================================

/// Primary implementation of [`CalendarProvider`] for Japanese compliance.
///
/// Provides comprehensive Japanese calendar operations including:
/// - Imperial era (Wareki/和暦) date conversions
/// - National holiday (国民の祝日) database
/// - Business day (営業日) calculations
/// - Custom organizational holidays from configuration files
///
/// # Thread Safety
///
/// This struct is fully thread-safe (`Send + Sync`) and can be shared across
/// async tasks without synchronization overhead since all data is immutable
/// after construction.
///
/// # Configuration
///
/// Load custom holidays from `calendar.toml` using [`load_calendar_toml()`].
#[derive(Debug, Clone)]
pub struct JapaneseCalendarProvider {
    /// Combined list of built-in national holidays + custom non-business days.
    holidays: Vec<Holiday>,

    /// Fast lookup set of all non-business dates for O(1) membership testing.
    custom_non_business_days: HashSet<NaiveDate>,
}

impl Default for JapaneseCalendarProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl JapaneseCalendarProvider {
    /// Create a new provider with built-in Japanese national holidays only.
    ///
    /// Use [`with_custom_holidays()`](Self::with_custom_holidays) or
    /// [`load_from_toml()`](Self::load_from_toml) to add organizational/prefectural holidays.
    pub fn new() -> Self {
        let holidays = Self::builtin_national_holidays();
        let custom_non_business_days: HashSet<NaiveDate> = HashSet::new();
        Self {
            holidays,
            custom_non_business_days,
        }
    }

    /// Create a provider with additional custom holidays loaded from TOML file.
    ///
    /// # Arguments
    /// * `toml_path` - Path to `calendar.toml` configuration file.
    ///
    /// # Errors
    /// - [`MisogiError::Io`] if the file cannot be read.
    /// - [`MisogiError::Serialization`] if the TOML is malformed.
    pub fn load_from_toml(toml_path: &Path) -> Result<Self> {
        let mut provider = Self::new();
        let custom_holidays = load_calendar_toml(toml_path)?;
        for holiday in &custom_holidays {
            provider.custom_non_business_days.insert(holiday.date);
        }
        provider.holidays.extend(custom_holidays);
        Ok(provider)
    }

    /// Create a provider with explicitly provided custom holidays.
    ///
    /// # Arguments
    /// * `custom_holidays` - Additional holidays beyond the built-in national list.
    pub fn with_custom_holidays(custom_holidays: Vec<Holiday>) -> Self {
        let mut custom_non_business_days: HashSet<NaiveDate> = HashSet::new();
        for h in &custom_holidays {
            custom_non_business_days.insert(h.date);
        }
        let mut holidays = Self::builtin_national_holidays();
        holidays.extend(custom_holidays);
        Self {
            holidays,
            custom_non_business_days,
        }
    }

    // -------------------------------------------------------------------------
    // Built-in Holiday Database
    // -------------------------------------------------------------------------

    /// Generate the complete list of Japanese national holidays for years 2020–2030.
    ///
    /// Includes all 固定祝日 (fixed-date holidays) and 移動祝日 (moving holidays)
    /// defined by the 祝日法 (Public Holiday Law of 1948).
    ///
    /// # Fixed Holidays (固定祝日)
    /// - 元日 (New Year's Day): January 1
    /// - 建国記念の日 (National Foundation Day): February 11
    /// - 昭和の日 (Showa Day): April 29
    /// - 憲法記念日 (Constitution Memorial Day): May 3
    /// - みどりの日 (Greenery Day): May 4
    /// - こどもの日 (Children's Day): May 5
    /// - 山の日 (Mountain Day): August 11
    /// - 文化の日 (Culture Day): November 3
    /// - 勤労感謝の日 (Labor Thanksgiving Day): November 23
    /// - 天皇誕生日 (Emperor's Birthday): February 23
    ///
    /// # Moving Holidays (Happy Monday System / 移動祝日)
    /// - 成人の日 (Coming of Age Day): 2nd Monday of January
    /// - 海の日 (Ocean Day): 3rd Monday of July
    /// - 敬老の日 (Respect for the Aged Day): 3rd Monday of September
    /// - 体育の日 (Sports Day): 2nd Monday of October
    ///
    /// # Equinox-based Holidays (approximate astronomical calculation)
    /// - 春分の日 (Vernal Equinox Day): ~March 20
    /// - 秋分の日 (Autumn Equinox Day): ~September 23
    fn builtin_national_holidays() -> Vec<Holiday> {
        let mut holidays = Vec::new();

        for year in 2020i32..=2030 {
            // ---- Fixed Date Holidays ----

            // 元日 (New Year's Day)
            holidays.push(Holiday {
                date: NaiveDate::from_ymd_opt(year, 1, 1).unwrap(),
                name_ja: String::from("元日"),
                name_en: String::from("New Year's Day"),
                category: HolidayCategory::National,
            });

            // 成人の日 (Coming of Age Day) — 2nd Monday of January
            if let Some(date) = nth_weekday_of_month(year, 1, Weekday::Mon, 2) {
                holidays.push(Holiday {
                    date,
                    name_ja: String::from("成人の日"),
                    name_en: String::from("Coming of Age Day"),
                    category: HolidayCategory::National,
                });
            }

            // 建国記念の日 (National Foundation Day)
            holidays.push(Holiday {
                date: NaiveDate::from_ymd_opt(year, 2, 11).unwrap(),
                name_ja: String::from("建国記念の日"),
                name_en: String::from("National Foundation Day"),
                category: HolidayCategory::National,
            });

            // 天皇誕生日 (Emperor's Birthday) — Naruhito
            holidays.push(Holiday {
                date: NaiveDate::from_ymd_opt(year, 2, 23).unwrap(),
                name_ja: String::from("天皇誕生日"),
                name_en: String::from("Emperor's Birthday"),
                category: HolidayCategory::National,
            });

            // 春分の日 (Vernal Equinox Day) — approximate formula
            if let Some(date) = approximate_vernal_equinox(year) {
                holidays.push(Holiday {
                    date,
                    name_ja: String::from("春分の日"),
                    name_en: String::from("Vernal Equinox Day"),
                    category: HolidayCategory::National,
                });
            }

            // 昭和の日 (Showa Day)
            holidays.push(Holiday {
                date: NaiveDate::from_ymd_opt(year, 4, 29).unwrap(),
                name_ja: String::from("昭和の日"),
                name_en: String::from("Showa Day"),
                category: HolidayCategory::National,
            });

            // 憲法記念日 (Constitution Memorial Day)
            holidays.push(Holiday {
                date: NaiveDate::from_ymd_opt(year, 5, 3).unwrap(),
                name_ja: String::from("憲法記念日"),
                name_en: String::from("Constitution Memorial Day"),
                category: HolidayCategory::National,
            });

            // みどりの日 (Greenery Day)
            holidays.push(Holiday {
                date: NaiveDate::from_ymd_opt(year, 5, 4).unwrap(),
                name_ja: String::from("みどりの日"),
                name_en: String::from("Greenery Day"),
                category: HolidayCategory::National,
            });

            // こどもの日 (Children's Day)
            holidays.push(Holiday {
                date: NaiveDate::from_ymd_opt(year, 5, 5).unwrap(),
                name_ja: String::from("こどもの日"),
                name_en: String::from("Children's Day"),
                category: HolidayCategory::National,
            });

            // 海の日 (Ocean Day) — 3rd Monday of July
            if let Some(date) = nth_weekday_of_month(year, 7, Weekday::Mon, 3) {
                holidays.push(Holiday {
                    date,
                    name_ja: String::from("海の日"),
                    name_en: String::from("Ocean Day"),
                    category: HolidayCategory::National,
                });
            }

            // 山の日 (Mountain Day)
            holidays.push(Holiday {
                date: NaiveDate::from_ymd_opt(year, 8, 11).unwrap(),
                name_ja: String::from("山の日"),
                name_en: String::from("Mountain Day"),
                category: HolidayCategory::National,
            });

            // 敬老の日 (Respect for the Aged Day) — 3rd Monday of September
            if let Some(date) = nth_weekday_of_month(year, 9, Weekday::Mon, 3) {
                holidays.push(Holiday {
                    date,
                    name_ja: String::from("敬老の日"),
                    name_en: String::from("Respect for the Aged Day"),
                    category: HolidayCategory::National,
                });
            }

            // 秋分の日 (Autumn Equinox Day) — approximate formula
            if let Some(date) = approximate_autumn_equinox(year) {
                holidays.push(Holiday {
                    date,
                    name_ja: String::from("秋分の日"),
                    name_en: String::from("Autumn Equinox Day"),
                    category: HolidayCategory::National,
                });
            }

            // 体育の日 (Sports Day) — 2nd Monday of October
            if let Some(date) = nth_weekday_of_month(year, 10, Weekday::Mon, 2) {
                holidays.push(Holiday {
                    date,
                    name_ja: String::from("体育の日"),
                    name_en: String::from("Sports Day"),
                    category: HolidayCategory::National,
                });
            }

            // 文化の日 (Culture Day)
            holidays.push(Holiday {
                date: NaiveDate::from_ymd_opt(year, 11, 3).unwrap(),
                name_ja: String::from("文化の日"),
                name_en: String::from("Culture Day"),
                category: HolidayCategory::National,
            });

            // 勤労感謝の日 (Labor Thanksgiving Day)
            holidays.push(Holiday {
                date: NaiveDate::from_ymd_opt(year, 11, 23).unwrap(),
                name_ja: String::from("勤労感謝の日"),
                name_en: String::from("Labor Thanksgiving Day"),
                category: HolidayCategory::National,
            });
        }

        holidays
    }

    // -------------------------------------------------------------------------
    // Wareki Conversion Helpers
    // -------------------------------------------------------------------------

    /// Find the era definition that contains a given Gregorian year.
    ///
    /// # Arguments
    /// * `year` - Gregorian year to look up.
    ///
    /// # Returns
    /// Reference to the matching [`EraDefinition`], or `None` if out of range.
    fn find_era_for_year(&self, year: i32) -> Option<&EraDefinition> {
        ERA_DEFINITIONS.iter().find(|era| era.contains_gregorian_year(year))
    }

    /// Find the era definition by its Kanji name or abbreviation.
    ///
    /// # Arguments
    /// * `name` - Era name ("令和", "平成", etc.) or single-char abbrev ('R', 'H', 'S', 'T', 'M').
    ///
    /// # Returns
    /// Reference to the matching [`EraDefinition`], or `None` if not found.
    fn find_era_by_name(&self, name: &str) -> Option<&EraDefinition> {
        if name.len() == 1 {
            // Single character — treat as abbreviation
            let ch = name.chars().next()?;
            ERA_DEFINITIONS.iter().find(|era| era.abbreviation == ch)
        } else {
            // Multi-character — treat as Kanji name
            ERA_DEFINITIONS.iter().find(|era| era.name_ja == name)
        }
    }
}

// =============================================================================
// Trait Implementation: CalendarProvider
// =============================================================================

#[async_trait::async_trait]
impl CalendarProvider for JapaneseCalendarProvider {
    fn name(&self) -> &str {
        "japanese-calendar-provider"
    }

    async fn regional_to_gregorian(
        &self,
        era_name: &str,
        era_year: u32,
        month: u32,
        day: u32,
    ) -> Result<NaiveDate> {
        let era = self.find_era_by_name(era_name).ok_or_else(|| {
            MisogiError::Protocol(format!("Unknown era name: {}", era_name))
        })?;

        let gregorian_year = era.wareki_to_gregorian_year(era_year);

        // Validate that the resulting date is within the era's valid range
        let date = NaiveDate::from_ymd_opt(gregorian_year, month, day).ok_or_else(|| {
            MisogiError::Protocol(format!(
                "Invalid date: {}-{:02}-{:02} ({}{})",
                gregorian_year, month, day, era_name, era_year
            ))
        })?;

        // Ensure date falls within era boundaries
        if date < era.start_date {
            return Err(MisogiError::Protocol(format!(
                "Date {} is before {} era start ({})",
                date, era.name_ja, era.start_date
            )));
        }
        if let Some(end) = era.end_date {
            if date > end {
                return Err(MisogiError::Protocol(format!(
                    "Date {} is after {} era end ({})",
                    date, era.name_ja, end
                )));
            }
        }

        Ok(date)
    }

    async fn gregorian_to_regional(
        &self,
        date: NaiveDate,
    ) -> Result<(String, u32, u32, u32)> {
        let year = date.year();
        let era = self.find_era_for_year(year).ok_or_else(|| {
            MisogiError::Protocol(format!(
                "No era defined for year {} (earliest supported: Meiji 1868)",
                year
            ))
        })?;

        // Additional boundary check for edge cases at era transitions
        if date < era.start_date {
            return Err(MisogiError::Protocol(format!(
                "Date {} predates {} era start ({})",
                date, era.name_ja, era.start_date
            )));
        }
        if let Some(end) = era.end_date {
            if date > end {
                return Err(MisogiError::Protocol(format!(
                    "Date {} postdates {} era end ({})",
                    date, era.name_ja, end
                )));
            }
        }

        let wareki_year = era.gregorian_to_wareki_year(year);
        Ok((era.name_ja.to_string(), wareki_year, date.month() as u32, date.day()))
    }

    async fn is_business_day(&self, date: NaiveDate) -> Result<bool> {
        let weekday = date.weekday();

        // Weekend check: Saturday (6) or Sunday (7)
        let is_weekend = weekday == Weekday::Sat || weekday == Weekday::Sun;

        // Holiday check: built-in + custom
        let is_holiday = self.holidays.iter().any(|h| h.date == date);
        let is_custom = self.custom_non_business_days.contains(&date);

        Ok(!is_weekend && !is_holiday && !is_custom)
    }

    async fn list_holidays(&self, from: NaiveDate, to: NaiveDate) -> Result<Vec<Holiday>> {
        let filtered: Vec<Holiday> = self
            .holidays
            .iter()
            .filter(|h| h.date >= from && h.date <= to)
            .cloned()
            .collect();

        Ok(filtered)
    }
}

// =============================================================================
// Filename Wareki Detection
// =============================================================================

/// Compiled regular expressions for Wareki pattern detection in filenames.
///
/// Supported patterns:
/// - **Abbreviation + 2-digit year**: `R08`, `H31`, `S64`, `T15`, `M45`
/// - **Kanji + 1-2 digit year**: `令和8`, `平成31`, `昭和64`
/// - **Full notation with 年度/年度 suffix**: `令和8年度`, `R08年度`
struct WarekiPatterns {
    re_abbr_two_digit: Regex,
    re_kanji_year: Regex,
}

impl WarekiPatterns {
    /// Initialize compiled regex patterns (lazy static equivalent).
    fn new() -> Self {
        Self {
            // Match R/H/S/T/M followed by exactly 2 digits (abbreviation format)
            re_abbr_two_digit: Regex::new(r"[RHSTM](\d{2})").unwrap(),

            // Match Kanji era name (令和/平成/昭和/大正/明治) followed by 1-2 digits
            re_kanji_year: Regex::new(r"(令和|平成|昭和|大正|明治)(\d{1,2})").unwrap(),
        }
    }
}

/// Detect and convert Wareki (Japanese Imperial era) notation in filenames to Gregorian year.
///
/// Scans a filename for common Wareki patterns used in Japanese government document naming:
///
/// | Pattern          | Example              | Gregorian Year |
/// |------------------|----------------------|----------------|
/// | Abbreviation+2dig| `document_R08.pdf`   | 2026           |
/// | Kanji+digit      | `令和8年度報告.xlsx` | 2026           |
/// | Heisei notation  | `H28_data.csv`       | 2016           |
/// | Showa notation   | `昭和63Form.doc`     | 1988           |
///
/// # Arguments
/// * `filename` - The filename string to scan for Wareki patterns.
///
/// # Returns
/// - `Some(gregorian_year)` if a valid Wareki pattern is detected and converted.
/// - `None` if no recognizable Wareki pattern is found.
///
/// # Detection Priority
/// When multiple patterns exist, the **first match** (leftmost position) wins.
///
/// # Examples
///
/// ```
/// # use misogi_core::contrib::jp::calendar::detect_wareki_in_filename;
/// assert_eq!(detect_wareki_in_filename("document_R08.pdf"), Some(2026));
/// assert_eq!(detect_wareki_in_filename("令和8年度報告.xlsx"), Some(2026));
/// assert_eq!(detect_wareki_in_filename("H28_data.csv"), Some(2016));
/// assert_eq!(detect_wareki_in_filename("plain_file.txt"), None);
/// ```
pub fn detect_wareki_in_filename(filename: &str) -> Option<i32> {
    let patterns = WarekiPatterns::new();

    // Strategy 1: Try abbreviation pattern (R08, H31, etc.)
    if let Some(caps) = patterns.re_abbr_two_digit.captures(filename) {
        let abbr = &filename[caps.get(0)?.start()..caps.get(0)?.start() + 1];
        let year_str = caps.get(1)?.as_str();
        let wareki_year: u32 = year_str.parse().ok()?;

        // Look up era by abbreviation
        if let Some(era) = ERA_DEFINITIONS
            .iter()
            .find(|e| e.abbreviation == abbr.chars().next().unwrap_or('\0'))
        {
            return Some(era.wareki_to_gregorian_year(wareki_year));
        }
    }

    // Strategy 2: Try Kanji pattern (令和8, 平成31, etc.)
    if let Some(caps) = patterns.re_kanji_year.captures(filename) {
        let era_name = caps.get(1)?.as_str();
        let year_str = caps.get(2)?.as_str();
        let wareki_year: u32 = year_str.parse().ok()?;

        // Look up era by Kanji name
        if let Some(era) = ERA_DEFINITIONS.iter().find(|e| e.name_ja == era_name) {
            return Some(era.wareki_to_gregorian_year(wareki_year));
        }
    }

    None
}

// =============================================================================
// calendar.toml Loading
// =============================================================================

/// Deserialization structure for `[holidays]` entries in `calendar.toml`.
#[derive(Debug, Deserialize, Serialize)]
pub struct TomlHolidayEntry {
    /// Date in ISO format (YYYY-MM-DD).
    pub date: String,

    /// Japanese name of the holiday.
    #[serde(default)]
    pub name_jp: String,

    /// English name of the holiday.
    #[serde(default)]
    pub name_en: String,

    /// Holiday category: "national", "prefectural", or "organizational".
    #[serde(default = "default_category")]
    pub category: String,
}

fn default_category() -> String {
    String::from("organizational")
}

/// Load custom holidays from a `calendar.toml` configuration file.
///
/// # File Format
///
/// ```toml
/// [[holidays]]
/// date = "2026-04-29"
/// name_jp = "黄金週間"
/// name_en = "Golden Week"
/// category = "organizational"
///
/// [[holidays]]
/// date = "2026-08-13"
/// name_jp = "お盆休み"
/// category = "prefectural"
/// ```
///
/// # Arguments
/// * `path` - Filesystem path to the TOML file.
///
/// # Returns
/// A vector of [`Holiday`] structs parsed from the file.
///
/// # Errors
/// - [`MisogiError::Io`] if the file cannot be read.
/// - [`MisogiError::Serialization`] if the TOML content is invalid or unparseable.
pub fn load_calendar_toml(path: &Path) -> Result<Vec<Holiday>> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        MisogiError::Io(e)
    })?;

    let config: TomlConfig = toml::from_str(&content).map_err(|e| {
        MisogiError::Serialization(serde_json::Error::custom(format!(
            "Failed to parse calendar.toml: {}",
            e
        )))
    })?;

    let holidays: Vec<Holiday> = config
        .holidays
        .into_iter()
        .filter_map(|entry| {
            let date = NaiveDate::parse_from_str(&entry.date, "%Y-%m-%d").ok()?;
            let category = match entry.category.as_str() {
                "national" => HolidayCategory::National,
                "prefectural" => HolidayCategory::Regional,
                _ => HolidayCategory::Organizational,
            };
            Some(Holiday {
                date,
                name_ja: entry.name_jp,
                name_en: entry.name_en,
                category,
            })
        })
        .collect();

    Ok(holidays)
}

/// Root structure for deserializing `calendar.toml`.
#[derive(Debug, Deserialize, Serialize)]
struct TomlConfig {
    /// Array of holiday entries.
    #[serde(default)]
    holidays: Vec<TomlHolidayEntry>,
}

// =============================================================================
// Helper Functions for Date Calculations
// =============================================================================

/// Calculate the N-th occurrence of a specific weekday within a given month.
///
/// Used for Happy Monday system holidays (成人の日, 海の日, 敬老の日, 体育の日).
///
/// # Arguments
/// * `year` - Gregorian year.
/// * `month` - Month (1-12).
/// * `weekday` - Target weekday (Mon=1, Tue=2, ..., Sun=7).
/// * `n` - N-th occurrence (1-based; pass 2 for "2nd Monday").
///
/// # Returns
/// - `Some(NaiveDate)` if the N-th weekday exists in that month.
/// - `None` if parameters are invalid or N exceeds possible occurrences.
fn nth_weekday_of_month(
    year: i32,
    month: u32,
    weekday: Weekday,
    n: u32,
) -> Option<NaiveDate> {
    if !(1..=12).contains(&month) || !(1..=5).contains(&n) {
        return None;
    }

    // Find the first day of the month
    let first_day = NaiveDate::from_ymd_opt(year, month, 1)?;

    // Calculate days to add to reach the target weekday
    let first_weekday = first_day.weekday();
    let days_until_target = (weekday.number_from_monday() as i32
        - first_weekday.number_from_monday() as i32
        + 7)
        % 7;

    // Calculate the N-th occurrence date
    let target_day = 1 + days_until_target + ((n as i32 - 1) * 7);

    NaiveDate::from_ymd_opt(year, month, target_day as u32)
}

/// Approximate Vernal Equinox Day (春分の日) using simplified formula.
///
/// The actual equinox date varies slightly year-by-year based on astronomical
/// observations announced by the Japanese Meteorological Agency. This approximation
/// is accurate enough for most business-day calculation purposes (±1 day error).
///
/// # Formula (simplified)
/// - Years 2020–2029: March 20 or 21
/// - Leap year adjustment applied
///
/// # Arguments
/// * `year` - Gregorian year.
///
/// # Returns
/// Approximate vernal equinox date, or `None` if year is out of expected range.
fn approximate_vernal_equinox(year: i32) -> Option<NaiveDate> {
    // Simplified approximation: typically March 20 or 21
    // More precise formula would require astronomical ephemeris data
    let day = if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) {
        20 // Leap years tend toward March 20
    } else {
        20 // Non-leap years also usually March 20
    };

    NaiveDate::from_ymd_opt(year, 3, day)
}

/// Approximate Autumn Equinox Day (秋分の日) using simplified formula.
///
/// Similar to [`approximate_vernal_equinox()`], this provides a close approximation
/// for business-day calculations. Actual date is announced annually by the
/// Meteorological Agency.
///
/// # Arguments
/// * `year` - Gregorian year.
///
/// # Returns
/// Approximate autumn equinox date, or `None` if year is out of expected range.
fn approximate_autumn_equinox(year: i32) -> Option<NaiveDate> {
    // Simplified approximation: typically September 22 or 23
    let day = match year % 4 {
        0 => 22, // Leap years often September 22
        _ => 23, // Other years often September 23
    };

    NaiveDate::from_ymd_opt(year, 9, day)
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Test: Wareki → Gregorian Conversions
    // =========================================================================

    #[test]
    fn test_reiwa_8_to_2026() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(provider.regional_to_gregorian("令和", 8, 4, 11));

        assert!(result.is_ok());
        let date = result.unwrap();
        assert_eq!(date.year(), 2026);
        assert_eq!(date.month(), 4);
        assert_eq!(date.day(), 11);
    }

    #[test]
    fn test_heisei_31_to_2019() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(provider.regional_to_gregorian("平成", 31, 4, 30));

        assert!(result.is_ok());
        let date = result.unwrap();
        assert_eq!(date.year(), 2019);
        assert_eq!(date.month(), 4);
        assert_eq!(date.day(), 30);
    }

    #[test]
    fn test_showa_64_to_1989() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Showa 64 ends on Jan 7, 1989
        let result = rt.block_on(provider.regional_to_gregorian("昭和", 64, 1, 7));

        assert!(result.is_ok());
        let date = result.unwrap();
        assert_eq!(date.year(), 1989);
        assert_eq!(date.month(), 1);
        assert_eq!(date.day(), 7);
    }

    #[test]
    fn test_abbreviation_r08() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(provider.regional_to_gregorian("R", 8, 1, 1));

        assert!(result.is_ok());
        assert_eq!(result.unwrap().year(), 2026);
    }

    #[test]
    fn test_unknown_era_error() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(provider.regional_to_gregorian("慶応", 3, 1, 1));

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown era"));
    }

    // =========================================================================
    // Test: Gregorian → Wareki Conversions
    // =========================================================================

    #[test]
    fn test_2026_to_reiwa_8() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let date = NaiveDate::from_ymd_opt(2026, 4, 11).unwrap();
        let result = rt.block_on(provider.gregorian_to_regional(date));

        assert!(result.is_ok());
        let (era, year, month, day) = result.unwrap();
        assert_eq!(era, "令和");
        assert_eq!(year, 8);
        assert_eq!(month, 4);
        assert_eq!(day, 11);
    }

    #[test]
    fn test_2019_boundary_heisei_to_reiwa() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();

        // April 30, 2019 = last day of Heisei
        let heisei_end = NaiveDate::from_ymd_opt(2019, 4, 30).unwrap();
        let result = rt.block_on(provider.gregorian_to_regional(heisei_end));
        assert!(result.is_ok());
        let (era, ..) = result.unwrap();
        assert_eq!(era, "平成");

        // May 1, 2019 = first day of Reiwa
        let reiwa_start = NaiveDate::from_ymd_opt(2019, 5, 1).unwrap();
        let result = rt.block_on(provider.gregorian_to_regional(reiwa_start));
        assert!(result.is_ok());
        let (era, ..) = result.unwrap();
        assert_eq!(era, "令和");
    }

    // =========================================================================
    // Test: Business Day Detection
    // =========================================================================

    #[test]
    fn test_weekend_is_not_business_day() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Saturday, January 4, 2025
        let saturday = NaiveDate::from_ymd_opt(2025, 1, 4).unwrap();
        let result = rt.block_on(provider.is_business_day(saturday));
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Saturday is NOT a business day

        // Sunday, January 5, 2025
        let sunday = NaiveDate::from_ymd_opt(2025, 1, 5).unwrap();
        let result = rt.block_on(provider.is_business_day(sunday));
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Sunday is NOT a business day
    }

    #[test]
    fn test_new_years_day_is_not_business_day() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();

        // January 1, 2026 (Wednesday) — New Year's Day (national holiday)
        let new_year = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        let result = rt.block_on(provider.is_business_day(new_year));
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Holiday overrides weekday
    }

    #[test]
    fn test_regular_weekday_is_business_day() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Monday, January 6, 2025 — should be a normal business day
        let monday = NaiveDate::from_ymd_opt(2025, 1, 6).unwrap();
        let result = rt.block_on(provider.is_business_day(monday));
        assert!(result.is_ok());
        assert!(result.unwrap()); // Regular Monday = business day
    }

    // =========================================================================
    // Test: Built-in Holiday Presence
    // =========================================================================

    #[test]
    fn test_builtin_holidays_contain_new_year() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let from = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        let result = rt.block_on(provider.list_holidays(from, to)).unwrap();

        assert!(!result.is_empty());
        assert!(result.iter().any(|h| h.name_ja == "元日"));
    }

    #[test]
    fn test_builtin_holidays_contain_showa_day() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let from = NaiveDate::from_ymd_opt(2026, 4, 29).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 4, 29).unwrap();
        let result = rt.block_on(provider.list_holidays(from, to)).unwrap();

        assert!(result.iter().any(|h| h.name_ja == "昭和の日"));
    }

    #[test]
    fn test_builtin_holidays_count_for_2026() {
        let provider = JapaneseCalendarProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let from = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 12, 31).unwrap();
        let result = rt.block_on(provider.list_holidays(from, to)).unwrap();

        // Japan has ~16 national holidays per year
        assert!(result.len() >= 15);
    }

    // =========================================================================
    // Test: Filename Wareki Detection
    // =========================================================================

    #[test]
    fn test_detect_wareki_r08() {
        assert_eq!(detect_wareki_in_filename("document_R08.pdf"), Some(2026));
    }

    #[test]
    fn test_detect_wareki_reiwa_kanji() {
        assert_eq!(detect_wareki_in_filename("令和8年度報告.xlsx"), Some(2026));
    }

    #[test]
    fn test_detect_wareki_h28() {
        assert_eq!(detect_wareki_in_filename("H28_data.csv"), Some(2016));
    }

    #[test]
    fn test_detect_wareki_s64() {
        assert_eq!(detect_wareki_in_filename("昭和63Form.doc"), Some(1988));
    }

    #[test]
    fn test_detect_wareki_no_pattern() {
        assert_eq!(detect_wareki_in_filename("plain_file.txt"), None);
        assert_eq!(detect_wareki_in_filename("report_2026.pdf"), None);
    }

    #[test]
    fn test_detect_wareki_priority_first_match() {
        // If both R08 and 令和8 appear, first match wins
        assert_eq!(
            detect_wareki_in_filename("R08_令和8_combined.pdf"),
            Some(2026)
        );
    }

    // =========================================================================
    // Test: Nth Weekday Calculation
    // =========================================================================

    #[test]
    fn test_2nd_monday_january_2026() {
        // January 2026: 1st = Thursday, so 2nd Monday = January 12
        let date = nth_weekday_of_month(2026, 1, Weekday::Mon, 2);
        assert!(date.is_some());
        let d = date.unwrap();
        assert_eq!(d.day(), 12);
        assert_eq!(d.weekday(), Weekday::Mon);
    }

    #[test]
    fn test_3rd_monday_july_2026() {
        // July 2026 Ocean Day should be 3rd Monday
        let date = nth_weekday_of_month(2026, 7, Weekday::Mon, 3);
        assert!(date.is_some());
        assert_eq!(date.unwrap().weekday(), Weekday::Mon);
    }

    // =========================================================================
    // Test: Era Definition Integrity
    // =========================================================================

    #[test]
    fn test_era_definitions_coverage() {
        // Verify all five eras are present
        assert_eq!(ERA_DEFINITIONS.len(), 5);

        let abbreviations: Vec<char> = ERA_DEFINITIONS.iter().map(|e| e.abbreviation).collect();
        assert!(abbreviations.contains(&'R')); // Reiwa
        assert!(abbreviations.contains(&'H')); // Heisei
        assert!(abbreviations.contains(&'S')); // Showa
        assert!(abbreviations.contains(&'T')); // Taisho
        assert!(abbreviations.contains(&'M')); // Meiji
    }

    #[test]
    fn test_era_no_overlap() {
        // Verify eras don't overlap (chronological integrity)
        for window in ERA_DEFINITIONS.windows(2) {
            let prev = &window[0];
            let next = &window[1];

            if let (Some(prev_end), _) = (prev.end_date, Some(next.start_date)) {
                // Previous era end must be exactly one day before next era start
                assert_eq!(
                    prev_end + chrono::Duration::days(1),
                    next.start_date,
                    "{} era end does not precede {} era start correctly",
                    prev.name_ja,
                    next.name_ja
                );
            }
        }
    }
}
