use rsiprtp::media::{generate_dtmf_tone, is_silence, WavReader};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn build_wav_header(
    sample_rate: u32,
    channels: u16,
    bits_per_sample: u16,
    data_size: u32,
) -> Vec<u8> {
    let byte_rate = sample_rate * channels as u32 * (bits_per_sample / 8) as u32;
    let block_align = channels * (bits_per_sample / 8);
    let file_size = 36 + data_size;

    let mut header = Vec::with_capacity(44);
    header.extend_from_slice(b"RIFF");
    header.extend_from_slice(&file_size.to_le_bytes());
    header.extend_from_slice(b"WAVE");
    header.extend_from_slice(b"fmt ");
    header.extend_from_slice(&16u32.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    header.extend_from_slice(&channels.to_le_bytes());
    header.extend_from_slice(&sample_rate.to_le_bytes());
    header.extend_from_slice(&byte_rate.to_le_bytes());
    header.extend_from_slice(&block_align.to_le_bytes());
    header.extend_from_slice(&bits_per_sample.to_le_bytes());
    header.extend_from_slice(b"data");
    header.extend_from_slice(&data_size.to_le_bytes());
    header
}

fn write_temp_file(bytes: &[u8], label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("gabby_media_{label}_{nanos}.wav"));
    let mut file = File::create(&path).expect("create temp wav");
    file.write_all(bytes).expect("write temp wav");
    path
}

#[test]
fn test_media_is_silence_branches() {
    assert!(is_silence(&[], 0.01));

    let quiet = vec![10i16, -10, 5, -5];
    assert!(is_silence(&quiet, 0.5));

    let loud = vec![i16::MAX, i16::MIN];
    assert!(!is_silence(&loud, 0.1));
}

#[test]
fn test_media_wav_header_branches() {
    let header = build_wav_header(8000, 1, 16, 0);

    let valid_path = write_temp_file(&header, "valid");
    let valid = WavReader::open(&valid_path);
    std::fs::remove_file(&valid_path).ok();
    assert!(valid.is_ok());

    let mut bad_riff = header.clone();
    bad_riff[0..4].copy_from_slice(b"XXXX");
    let bad_riff_path = write_temp_file(&bad_riff, "bad_riff");
    let bad_riff_result = WavReader::open(&bad_riff_path);
    std::fs::remove_file(&bad_riff_path).ok();
    assert!(bad_riff_result.is_err());

    let mut bad_wave = header.clone();
    bad_wave[8..12].copy_from_slice(b"XXXX");
    let bad_wave_path = write_temp_file(&bad_wave, "bad_wave");
    let bad_wave_result = WavReader::open(&bad_wave_path);
    std::fs::remove_file(&bad_wave_path).ok();
    assert!(bad_wave_result.is_err());

    let mut bad_fmt = header.clone();
    bad_fmt[12..16].copy_from_slice(b"xxxx");
    let bad_fmt_path = write_temp_file(&bad_fmt, "bad_fmt");
    let bad_fmt_result = WavReader::open(&bad_fmt_path);
    std::fs::remove_file(&bad_fmt_path).ok();
    assert!(bad_fmt_result.is_err());

    let mut bad_pcm = header.clone();
    bad_pcm[20] = 3;
    bad_pcm[21] = 0;
    let bad_pcm_path = write_temp_file(&bad_pcm, "bad_pcm");
    let bad_pcm_result = WavReader::open(&bad_pcm_path);
    std::fs::remove_file(&bad_pcm_path).ok();
    assert!(bad_pcm_result.is_err());

    let mut bad_data = header.clone();
    bad_data[36..40].copy_from_slice(b"JUNK");
    let bad_data_path = write_temp_file(&bad_data, "bad_data");
    let bad_data_result = WavReader::open(&bad_data_path);
    std::fs::remove_file(&bad_data_path).ok();
    assert!(bad_data_result.is_err());
}

#[test]
fn test_media_generate_dtmf_branches() {
    let tone = generate_dtmf_tone('5', 50, 8000);
    assert!(!tone.is_empty());

    let invalid = generate_dtmf_tone('X', 50, 8000);
    assert!(invalid.is_empty());
}
