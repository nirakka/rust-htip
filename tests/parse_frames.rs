use rust_htip::Dispatcher;

#[test]
fn fuzzer_crash_bad_frame_length_fix() {
    let bytes = [222u8, 3u8, 0u8];

    let mut disp = Dispatcher::new();
    let _ = disp.parse(&bytes);
}
