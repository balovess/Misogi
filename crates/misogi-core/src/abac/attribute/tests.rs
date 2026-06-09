#[cfg(test)]
mod test_cases {
    use crate::abac::attribute::{AbacAttribute, AbacValue, DayMask, TimeWindow};
    // ===================================================================
    // AbacValue Conversion Tests
    // ===================================================================

    #[test]
    fn abac_value_string_as_str_returns_some() {
        let val = AbacValue::String("administrator".to_string());
        assert_eq!(val.as_str(), Some("administrator"));
    }

    #[test]
    fn abac_value_integer_as_str_returns_none() {
        let val = AbacValue::Integer(42);
        assert_eq!(val.as_str(), None);
    }

    #[test]
    fn abac_value_integer_as_i64_returns_value() {
        let val = AbacValue::Integer(-100);
        assert_eq!(val.as_i64(), Some(-100));
    }

    #[test]
    fn abac_value_string_as_i64_returns_none() {
        let val = AbacValue::String("not_a_number".to_string());
        assert_eq!(val.as_i64(), None);
    }

    #[test]
    fn abac_value_boolean_as_bool_returns_value() {
        assert_eq!(AbacValue::Boolean(true).as_bool(), Some(true));
        assert_eq!(AbacValue::Boolean(false).as_bool(), Some(false));
    }

    #[test]
    fn abac_value_list_as_bool_returns_none() {
        let val = AbacValue::List(vec![]);
        assert_eq!(val.as_bool(), None);
    }

    #[test]
    fn abac_value_type_name_returns_correct_names() {
        assert_eq!(AbacValue::String(String::new()).type_name(), "String");
        assert_eq!(AbacValue::Integer(0).type_name(), "Integer");
        assert_eq!(AbacValue::Float(0.0).type_name(), "Float");
        assert_eq!(AbacValue::Boolean(true).type_name(), "Boolean");
        assert_eq!(AbacValue::List(vec![]).type_name(), "List");
    }

    #[test]
    fn abac_value_equality_works_across_variants() {
        assert_eq!(
            AbacValue::String("test".to_string()),
            AbacValue::String("test".to_string())
        );
        assert_ne!(
            AbacValue::String("a".to_string()),
            AbacValue::String("b".to_string())
        );
        assert_eq!(AbacValue::Integer(10), AbacValue::Integer(10));
        assert_ne!(AbacValue::Boolean(true), AbacValue::Boolean(false));
    }

    // ===================================================================
    // TimeWindow Tests
    // ===================================================================

    #[test]
    fn time_window_contains_point_inside_window() {
        let tw = TimeWindow::new(9, 0, 17, 0);
        assert!(tw.contains(12, 30));
    }

    #[test]
    fn time_window_contains_start_boundary_inclusive() {
        let tw = TimeWindow::new(9, 0, 17, 0);
        assert!(tw.contains(9, 0));
    }

    #[test]
    fn time_window_excludes_end_boundary() {
        let tw = TimeWindow::new(9, 0, 17, 0);
        assert!(!tw.contains(17, 0));
    }

    #[test]
    fn time_window_rejects_outside_before_start() {
        let tw = TimeWindow::new(9, 0, 17, 0);
        assert!(!tw.contains(8, 59));
    }

    #[test]
    fn time_window_rejects_outside_after_end() {
        let tw = TimeWindow::new(9, 0, 17, 0);
        assert!(!tw.contains(17, 1));
    }

    // ===================================================================
    // DayMask Tests
    // ===================================================================

    #[test]
    fn daymask_from_weekday_monday_sets_correct_bit() {
        let mask = DayMask::from_weekday(1); // Monday
        assert!(mask.contains(1));
        assert!(!mask.contains(2)); // Tuesday not set
    }

    #[test]
    fn daymask_from_weekday_sunday_sets_bit_six() {
        let mask = DayMask::from_weekday(7); // Sunday
        assert!(mask.contains(7));
        assert!(!mask.contains(1)); // Monday not set
    }

    #[test]
    fn daymask_invalid_weekday_produces_empty_mask() {
        let mask = DayMask::from_weekday(0);
        assert!(!mask.contains(1));
        assert!(!mask.contains(7));
        assert_eq!(mask.as_bits(), 0);

        let mask2 = DayMask::from_weekday(99);
        assert_eq!(mask2.as_bits(), 0);
    }

    #[test]
    fn daymask_weekdays_contains_mon_to_fri_only() {
        let mask = DayMask::weekdays();
        assert!(mask.contains(1)); // Mon
        assert!(mask.contains(2)); // Tue
        assert!(mask.contains(3)); // Wed
        assert!(mask.contains(4)); // Thu
        assert!(mask.contains(5)); // Fri
        assert!(!mask.contains(6)); // Sat
        assert!(!mask.contains(7)); // Sun
    }

    #[test]
    fn daymask_every_day_contains_all_days() {
        let mask = DayMask::every_day();
        for d in 1..=7 {
            assert!(mask.contains(d), "every_day should contain weekday {}", d);
        }
    }

    #[test]
    fn daymask_empty_contains_nothing() {
        let mask = DayMask::empty();
        for d in 1..=7 {
            assert!(!mask.contains(d));
        }
    }

    // ===================================================================
    // AbacAttribute Tests
    // ===================================================================

    #[test]
    fn abac_attribute_user_id_equality() {
        let a = AbacAttribute::UserId("user-001".to_string());
        let b = AbacAttribute::UserId("user-001".to_string());
        let c = AbacAttribute::UserId("user-002".to_string());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn abac_attribute_different_variants_not_equal() {
        let a = AbacAttribute::Role("admin".to_string());
        let b = AbacAttribute::Department("admin".to_string());
        assert_ne!(a, b); // Same payload, different variant
    }

    #[test]
    fn abac_attribute_clearance_level_equality() {
        let a = AbacAttribute::ClearanceLevel(3);
        let b = AbacAttribute::ClearanceLevel(3);
        assert_eq!(a, b);
    }

    #[test]
    fn abac_attribute_custom_key_value_roundtrip() {
        let attr = AbacAttribute::Custom {
            key: "project_code".to_string(),
            value: AbacValue::String("PROJ-Alpha".to_string()),
        };
        match attr {
            AbacAttribute::Custom { key, value } => {
                assert_eq!(key, "project_code");
                assert_eq!(value.as_str().unwrap(), "PROJ-Alpha");
            }
            _ => panic!("Expected Custom variant"),
        }
    }
}
