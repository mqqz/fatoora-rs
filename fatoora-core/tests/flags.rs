use fatoora_core::invoice::InvoiceFlags;

#[test]
fn flags_keep_their_bits_and_serialization() {
    let mut flags = InvoiceFlags::EXPORT | InvoiceFlags::SELF_BILLED;
    assert_eq!(flags.bits(), 0b10100);
    assert_eq!(
        serde_json::to_string(&flags).unwrap(),
        "\"EXPORT | SELF_BILLED\""
    );
    let restored: InvoiceFlags = serde_json::from_str("\"EXPORT | SELF_BILLED\"").unwrap();
    assert_eq!(restored, flags);
    flags.set(InvoiceFlags::SELF_BILLED, false);
    flags.insert(InvoiceFlags::SUMMARY);
    assert_eq!(flags.bits(), 0b01100);
    assert_eq!((flags & InvoiceFlags::EXPORT).bits(), 0b00100);
    assert_eq!((flags - InvoiceFlags::EXPORT).bits(), 0b01000);
}

#[test]
fn owned_iterators_preserve_unknown_bits() {
    let flags = InvoiceFlags::from_bits_retain(0b1000_0100);
    assert_eq!(
        flags.iter().map(|value| value.bits()).collect::<Vec<_>>(),
        [4, 128]
    );
    assert_eq!(
        flags.iter_names().collect::<Vec<_>>(),
        [("EXPORT", InvoiceFlags::EXPORT)]
    );
    assert_eq!(flags.into_iter().collect::<InvoiceFlags>(), flags);
    assert!(InvoiceFlags::from_bits(128).is_none());
    assert_eq!(InvoiceFlags::from_bits_truncate(128), InvoiceFlags::empty());
    let json = serde_json::to_string(&flags).unwrap();
    assert_eq!(serde_json::from_str::<InvoiceFlags>(&json).unwrap(), flags);
}
