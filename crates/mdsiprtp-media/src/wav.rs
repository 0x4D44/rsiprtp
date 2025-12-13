//! WAV file recording and playback.
//!
//! Simple WAV file support for voicemail and audio file handling.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// WAV file writer for recording audio.
pub struct WavWriter {
    writer: BufWriter<File>,
    sample_rate: u32,
    channels: u16,
    bits_per_sample: u16,
    data_size: u32,
}

impl WavWriter {
    /// Create a new WAV writer.
    ///
    /// # Arguments
    /// * `path` - Output file path
    /// * `sample_rate` - Sample rate in Hz (e.g., 8000, 16000, 48000)
    /// * `channels` - Number of channels (1 for mono, 2 for stereo)
    /// * `bits_per_sample` - Bits per sample (typically 16)
    pub fn create<P: AsRef<Path>>(
        path: P,
        sample_rate: u32,
        channels: u16,
        bits_per_sample: u16,
    ) -> io::Result<Self> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        // Write placeholder header (will be updated on close)
        let header = build_wav_header(sample_rate, channels, bits_per_sample, 0);
        writer.write_all(&header)?;

        Ok(Self {
            writer,
            sample_rate,
            channels,
            bits_per_sample,
            data_size: 0,
        })
    }

    /// Create a mono 16-bit WAV writer (common for telephony).
    pub fn create_mono<P: AsRef<Path>>(path: P, sample_rate: u32) -> io::Result<Self> {
        Self::create(path, sample_rate, 1, 16)
    }

    /// Write audio samples.
    ///
    /// # Arguments
    /// * `samples` - 16-bit signed PCM samples
    pub fn write_samples(&mut self, samples: &[i16]) -> io::Result<()> {
        for &sample in samples {
            self.writer.write_all(&sample.to_le_bytes())?;
        }
        self.data_size += (samples.len() * 2) as u32;
        Ok(())
    }

    /// Write raw bytes directly.
    pub fn write_bytes(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(data)?;
        self.data_size += data.len() as u32;
        Ok(())
    }

    /// Get the current duration in seconds.
    pub fn duration_secs(&self) -> f64 {
        let bytes_per_sample = (self.bits_per_sample / 8) as u32;
        let bytes_per_second = self.sample_rate * self.channels as u32 * bytes_per_sample;
        self.data_size as f64 / bytes_per_second as f64
    }

    /// Finish writing and close the file.
    ///
    /// This updates the WAV header with the correct file size.
    pub fn finish(mut self) -> io::Result<()> {
        // Flush any buffered data
        self.writer.flush()?;

        // Seek back to header and update sizes
        let file = self.writer.get_mut();
        file.seek(SeekFrom::Start(0))?;

        let header = build_wav_header(
            self.sample_rate,
            self.channels,
            self.bits_per_sample,
            self.data_size,
        );
        file.write_all(&header)?;

        Ok(())
    }
}

/// WAV file reader for playback.
pub struct WavReader {
    reader: BufReader<File>,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// Number of channels.
    pub channels: u16,
    /// Bits per sample.
    pub bits_per_sample: u16,
    /// Total number of samples.
    pub num_samples: u32,
    /// Current sample position.
    position: u32,
}

impl WavReader {
    /// Open a WAV file for reading.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        // Parse WAV header
        let (sample_rate, channels, bits_per_sample, data_size) = parse_wav_header(&mut reader)?;

        let bytes_per_sample = (bits_per_sample / 8) as u32;
        let num_samples = data_size / (channels as u32 * bytes_per_sample);

        Ok(Self {
            reader,
            sample_rate,
            channels,
            bits_per_sample,
            num_samples,
            position: 0,
        })
    }

    /// Read a number of samples.
    ///
    /// Returns the samples read (may be less than requested at end of file).
    pub fn read_samples(&mut self, count: usize) -> io::Result<Vec<i16>> {
        let mut samples = Vec::with_capacity(count);
        let mut buf = [0u8; 2];

        for _ in 0..count {
            if self.position >= self.num_samples * self.channels as u32 {
                break;
            }

            if self.reader.read_exact(&mut buf).is_err() {
                break;
            }

            samples.push(i16::from_le_bytes(buf));
            self.position += 1;
        }

        Ok(samples)
    }

    /// Read a frame of samples (e.g., 20ms worth).
    ///
    /// # Arguments
    /// * `duration_ms` - Frame duration in milliseconds
    pub fn read_frame(&mut self, duration_ms: u32) -> io::Result<Vec<i16>> {
        let samples_per_frame = (self.sample_rate * duration_ms / 1000) as usize;
        self.read_samples(samples_per_frame * self.channels as usize)
    }

    /// Get the total duration in seconds.
    pub fn duration_secs(&self) -> f64 {
        self.num_samples as f64 / self.sample_rate as f64
    }

    /// Get the current position in seconds.
    pub fn position_secs(&self) -> f64 {
        let samples_read = self.position / self.channels as u32;
        samples_read as f64 / self.sample_rate as f64
    }

    /// Check if we've reached the end of the file.
    pub fn is_eof(&self) -> bool {
        self.position >= self.num_samples * self.channels as u32
    }

    /// Seek to a position in seconds.
    pub fn seek_secs(&mut self, secs: f64) -> io::Result<()> {
        let sample_pos = (secs * self.sample_rate as f64) as u32;
        let sample_pos = sample_pos.min(self.num_samples);

        let bytes_per_sample = (self.bits_per_sample / 8) as u64;
        let byte_pos = sample_pos as u64 * self.channels as u64 * bytes_per_sample;

        // Skip header (44 bytes) + data offset
        self.reader.seek(SeekFrom::Start(44 + byte_pos))?;
        self.position = sample_pos * self.channels as u32;

        Ok(())
    }

    /// Reset to the beginning of the audio data.
    pub fn rewind(&mut self) -> io::Result<()> {
        self.reader.seek(SeekFrom::Start(44))?;
        self.position = 0;
        Ok(())
    }
}

/// Build a WAV file header.
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

    // RIFF header
    header.extend_from_slice(b"RIFF");
    header.extend_from_slice(&file_size.to_le_bytes());
    header.extend_from_slice(b"WAVE");

    // fmt chunk
    header.extend_from_slice(b"fmt ");
    header.extend_from_slice(&16u32.to_le_bytes()); // Chunk size
    header.extend_from_slice(&1u16.to_le_bytes()); // Audio format (PCM)
    header.extend_from_slice(&channels.to_le_bytes());
    header.extend_from_slice(&sample_rate.to_le_bytes());
    header.extend_from_slice(&byte_rate.to_le_bytes());
    header.extend_from_slice(&block_align.to_le_bytes());
    header.extend_from_slice(&bits_per_sample.to_le_bytes());

    // data chunk
    header.extend_from_slice(b"data");
    header.extend_from_slice(&data_size.to_le_bytes());

    header
}

/// Parse a WAV file header.
fn parse_wav_header<R: Read + Seek>(reader: &mut R) -> io::Result<(u32, u16, u16, u32)> {
    let mut buf = [0u8; 44];
    reader.read_exact(&mut buf)?;

    // Verify RIFF header
    if &buf[0..4] != b"RIFF" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Not a RIFF file",
        ));
    }
    if &buf[8..12] != b"WAVE" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Not a WAVE file",
        ));
    }

    // Verify fmt chunk
    if &buf[12..16] != b"fmt " {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Missing fmt chunk",
        ));
    }

    // Parse format
    let audio_format = u16::from_le_bytes([buf[20], buf[21]]);
    if audio_format != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Only PCM format supported",
        ));
    }

    let channels = u16::from_le_bytes([buf[22], buf[23]]);
    let sample_rate = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
    let bits_per_sample = u16::from_le_bytes([buf[34], buf[35]]);

    // Verify data chunk
    if &buf[36..40] != b"data" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Missing data chunk",
        ));
    }

    let data_size = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);

    Ok((sample_rate, channels, bits_per_sample, data_size))
}

/// Generate a simple tone for testing or prompts.
///
/// # Arguments
/// * `frequency` - Tone frequency in Hz
/// * `duration_ms` - Duration in milliseconds
/// * `sample_rate` - Sample rate in Hz
/// * `amplitude` - Amplitude (0.0 to 1.0)
pub fn generate_tone(
    frequency: f64,
    duration_ms: u32,
    sample_rate: u32,
    amplitude: f64,
) -> Vec<i16> {
    let num_samples = (sample_rate * duration_ms / 1000) as usize;
    let amplitude = (amplitude * i16::MAX as f64) as i16;

    (0..num_samples)
        .map(|i| {
            let t = i as f64 / sample_rate as f64;
            let value = (2.0 * std::f64::consts::PI * frequency * t).sin();
            (value * amplitude as f64) as i16
        })
        .collect()
}

/// Generate DTMF tone (dual-tone).
///
/// # Arguments
/// * `digit` - DTMF digit (0-9, *, #, A-D)
/// * `duration_ms` - Duration in milliseconds
/// * `sample_rate` - Sample rate in Hz
pub fn generate_dtmf_tone(digit: char, duration_ms: u32, sample_rate: u32) -> Vec<i16> {
    let (low, high) = match digit {
        '1' => (697.0, 1209.0),
        '2' => (697.0, 1336.0),
        '3' => (697.0, 1477.0),
        'A' => (697.0, 1633.0),
        '4' => (770.0, 1209.0),
        '5' => (770.0, 1336.0),
        '6' => (770.0, 1477.0),
        'B' => (770.0, 1633.0),
        '7' => (852.0, 1209.0),
        '8' => (852.0, 1336.0),
        '9' => (852.0, 1477.0),
        'C' => (852.0, 1633.0),
        '*' => (941.0, 1209.0),
        '0' => (941.0, 1336.0),
        '#' => (941.0, 1477.0),
        'D' => (941.0, 1633.0),
        _ => return Vec::new(),
    };

    let num_samples = (sample_rate * duration_ms / 1000) as usize;
    let amplitude = 0.4 * i16::MAX as f64; // 40% for each tone

    (0..num_samples)
        .map(|i| {
            let t = i as f64 / sample_rate as f64;
            let low_val = (2.0 * std::f64::consts::PI * low * t).sin();
            let high_val = (2.0 * std::f64::consts::PI * high * t).sin();
            ((low_val + high_val) * amplitude / 2.0) as i16
        })
        .collect()
}

/// Generate silence.
pub fn generate_silence(duration_ms: u32, sample_rate: u32) -> Vec<i16> {
    let num_samples = (sample_rate * duration_ms / 1000) as usize;
    vec![0i16; num_samples]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_wav_header_build_parse() {
        let header = build_wav_header(8000, 1, 16, 16000);
        assert_eq!(header.len(), 44);

        // Verify RIFF
        assert_eq!(&header[0..4], b"RIFF");
        assert_eq!(&header[8..12], b"WAVE");

        // Parse it back
        let mut cursor = Cursor::new(header);
        let (sample_rate, channels, bits, data_size) = parse_wav_header(&mut cursor).unwrap();

        assert_eq!(sample_rate, 8000);
        assert_eq!(channels, 1);
        assert_eq!(bits, 16);
        assert_eq!(data_size, 16000);
    }

    #[test]
    fn test_generate_tone() {
        let tone = generate_tone(440.0, 100, 8000, 0.5);

        // 100ms at 8kHz = 800 samples
        assert_eq!(tone.len(), 800);

        // Should have some non-zero samples
        assert!(tone.iter().any(|&s| s != 0));

        // Should oscillate around zero
        let sum: i64 = tone.iter().map(|&s| s as i64).sum();
        let avg = sum / tone.len() as i64;
        assert!(avg.abs() < 1000); // Should average near zero
    }

    #[test]
    fn test_generate_dtmf() {
        let tone = generate_dtmf_tone('5', 100, 8000);
        assert_eq!(tone.len(), 800);
        assert!(tone.iter().any(|&s| s != 0));
    }

    #[test]
    fn test_generate_silence() {
        let silence = generate_silence(100, 8000);
        assert_eq!(silence.len(), 800);
        assert!(silence.iter().all(|&s| s == 0));
    }

    #[test]
    fn test_wav_roundtrip() {
        let temp_path = std::env::temp_dir().join("test_wav_roundtrip.wav");

        // Write
        {
            let mut writer = WavWriter::create_mono(&temp_path, 8000).unwrap();
            let samples: Vec<i16> = (0..160).map(|i| (i * 100) as i16).collect();
            writer.write_samples(&samples).unwrap();
            writer.finish().unwrap();
        }

        // Read
        {
            let mut reader = WavReader::open(&temp_path).unwrap();
            assert_eq!(reader.sample_rate, 8000);
            assert_eq!(reader.channels, 1);
            assert_eq!(reader.bits_per_sample, 16);

            let samples = reader.read_samples(160).unwrap();
            assert_eq!(samples.len(), 160);
            assert_eq!(samples[0], 0);
            assert_eq!(samples[1], 100);
        }

        // Cleanup
        std::fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn test_wav_reader_eof() {
        let temp_path = std::env::temp_dir().join("test_wav_eof.wav");

        {
            let mut writer = WavWriter::create_mono(&temp_path, 8000).unwrap();
            writer.write_samples(&[1, 2, 3, 4, 5]).unwrap();
            writer.finish().unwrap();
        }

        {
            let mut reader = WavReader::open(&temp_path).unwrap();
            assert!(!reader.is_eof());

            // Read all samples
            let samples = reader.read_samples(10).unwrap();
            assert_eq!(samples.len(), 5); // Only 5 available

            assert!(reader.is_eof());
        }

        std::fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn test_wav_seek() {
        let temp_path = std::env::temp_dir().join("test_wav_seek.wav");

        {
            let mut writer = WavWriter::create_mono(&temp_path, 8000).unwrap();
            // Write 1 second of audio (8000 samples)
            let samples: Vec<i16> = (0..8000).map(|i| i as i16).collect();
            writer.write_samples(&samples).unwrap();
            writer.finish().unwrap();
        }

        {
            let mut reader = WavReader::open(&temp_path).unwrap();
            assert_eq!(reader.duration_secs(), 1.0);

            // Seek to 0.5 seconds
            reader.seek_secs(0.5).unwrap();
            assert!((reader.position_secs() - 0.5).abs() < 0.001);

            // Read sample at that position
            let samples = reader.read_samples(1).unwrap();
            assert_eq!(samples[0], 4000); // Sample at index 4000

            // Rewind
            reader.rewind().unwrap();
            assert_eq!(reader.position_secs(), 0.0);
        }

        std::fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn test_wav_parse_invalid_riff() {
        // Invalid RIFF header
        let mut data = vec![0u8; 44];
        data[0..4].copy_from_slice(b"XXXX"); // Invalid magic
        data[8..12].copy_from_slice(b"WAVE");
        let mut cursor = Cursor::new(data);
        let result = parse_wav_header(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_wav_parse_invalid_wave() {
        // Invalid WAVE header
        let mut data = vec![0u8; 44];
        data[0..4].copy_from_slice(b"RIFF");
        data[8..12].copy_from_slice(b"XXXX"); // Invalid WAVE
        let mut cursor = Cursor::new(data);
        let result = parse_wav_header(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_wav_parse_missing_fmt() {
        // Missing fmt chunk
        let mut data = vec![0u8; 44];
        data[0..4].copy_from_slice(b"RIFF");
        data[8..12].copy_from_slice(b"WAVE");
        data[12..16].copy_from_slice(b"xxxx"); // Invalid fmt
        let mut cursor = Cursor::new(data);
        let result = parse_wav_header(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_wav_parse_non_pcm_format() {
        // Non-PCM format (e.g., compressed)
        let mut header = build_wav_header(8000, 1, 16, 1000);
        header[20] = 3; // Float format instead of PCM (1)
        header[21] = 0;
        let mut cursor = Cursor::new(header);
        let result = parse_wav_header(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_wav_parse_missing_data() {
        // Missing data chunk
        let mut data = vec![0u8; 44];
        data[0..4].copy_from_slice(b"RIFF");
        data[4..8].copy_from_slice(&40u32.to_le_bytes());
        data[8..12].copy_from_slice(b"WAVE");
        data[12..16].copy_from_slice(b"fmt ");
        data[16..20].copy_from_slice(&16u32.to_le_bytes()); // fmt chunk size
        data[20..22].copy_from_slice(&1u16.to_le_bytes()); // PCM format
        data[22..24].copy_from_slice(&1u16.to_le_bytes()); // channels
        data[24..28].copy_from_slice(&8000u32.to_le_bytes()); // sample rate
        data[28..32].copy_from_slice(&16000u32.to_le_bytes()); // byte rate
        data[32..34].copy_from_slice(&2u16.to_le_bytes()); // block align
        data[34..36].copy_from_slice(&16u16.to_le_bytes()); // bits per sample
        data[36..40].copy_from_slice(b"xxxx"); // Invalid data marker
        let mut cursor = Cursor::new(data);
        let result = parse_wav_header(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_wav_parse_truncated_header() {
        // Truncated header (less than 44 bytes)
        let data = vec![0u8; 20];
        let mut cursor = Cursor::new(data);
        let result = parse_wav_header(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_wav_stereo_roundtrip() {
        let temp_path = std::env::temp_dir().join("test_wav_stereo.wav");

        {
            let mut writer = WavWriter::create(&temp_path, 44100, 2, 16).unwrap();
            // Stereo samples: L, R, L, R...
            let samples: Vec<i16> = (0..200).map(|i| (i * 50) as i16).collect();
            writer.write_samples(&samples).unwrap();
            assert!(writer.duration_secs() > 0.0);
            writer.finish().unwrap();
        }

        {
            let mut reader = WavReader::open(&temp_path).unwrap();
            assert_eq!(reader.sample_rate, 44100);
            assert_eq!(reader.channels, 2);
            assert_eq!(reader.bits_per_sample, 16);
            let samples = reader.read_samples(200).unwrap();
            assert_eq!(samples.len(), 200);
        }

        std::fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn test_wav_read_frame() {
        let temp_path = std::env::temp_dir().join("test_wav_frame.wav");

        {
            let mut writer = WavWriter::create_mono(&temp_path, 8000).unwrap();
            let samples: Vec<i16> = (0..1600).map(|i| i as i16).collect();
            writer.write_samples(&samples).unwrap();
            writer.finish().unwrap();
        }

        {
            let mut reader = WavReader::open(&temp_path).unwrap();
            // Read 20ms frame at 8kHz = 160 samples
            let frame = reader.read_frame(20).unwrap();
            assert_eq!(frame.len(), 160);
            assert_eq!(frame[0], 0);
            assert_eq!(frame[159], 159);
        }

        std::fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn test_wav_write_bytes() {
        let temp_path = std::env::temp_dir().join("test_wav_bytes.wav");

        {
            let mut writer = WavWriter::create_mono(&temp_path, 8000).unwrap();
            // Write raw bytes (little-endian i16)
            let bytes: Vec<u8> = vec![0x00, 0x01, 0x00, 0x02]; // 256, 512
            writer.write_bytes(&bytes).unwrap();
            writer.finish().unwrap();
        }

        {
            let mut reader = WavReader::open(&temp_path).unwrap();
            let samples = reader.read_samples(2).unwrap();
            assert_eq!(samples[0], 256);
            assert_eq!(samples[1], 512);
        }

        std::fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn test_wav_seek_beyond_end() {
        let temp_path = std::env::temp_dir().join("test_wav_seek_beyond.wav");

        {
            let mut writer = WavWriter::create_mono(&temp_path, 8000).unwrap();
            let samples: Vec<i16> = vec![100; 800]; // 0.1 seconds
            writer.write_samples(&samples).unwrap();
            writer.finish().unwrap();
        }

        {
            let mut reader = WavReader::open(&temp_path).unwrap();
            // Seek beyond end should clamp to end
            reader.seek_secs(10.0).unwrap();
            // Position should be at or near end
            assert!(reader.position_secs() <= reader.duration_secs() + 0.001);
        }

        std::fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn test_generate_dtmf_invalid_digit() {
        let tone = generate_dtmf_tone('X', 100, 8000);
        assert!(tone.is_empty());
    }

    #[test]
    fn test_generate_dtmf_all_digits() {
        let digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#', 'A', 'B', 'C', 'D'];
        for digit in digits {
            let tone = generate_dtmf_tone(digit, 50, 8000);
            assert_eq!(tone.len(), 400); // 50ms at 8kHz
            assert!(tone.iter().any(|&s| s != 0));
        }
    }

    #[test]
    fn test_generate_tone_zero_amplitude() {
        let tone = generate_tone(440.0, 100, 8000, 0.0);
        assert_eq!(tone.len(), 800);
        assert!(tone.iter().all(|&s| s == 0));
    }

    #[test]
    fn test_generate_tone_various_rates() {
        for &rate in &[8000u32, 16000, 44100, 48000] {
            let tone = generate_tone(440.0, 100, rate, 0.5);
            let expected_len = (rate * 100 / 1000) as usize;
            assert_eq!(tone.len(), expected_len);
        }
    }
}
