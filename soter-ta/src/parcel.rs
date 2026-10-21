//! AIDL parcel codec for `vendor.qti.hardware.soter.ISoter`.
//!
//! Request layout (as written by the generated client stubs): one strict-mode
//! policy word, the interface token, then the method arguments. Reply layout: a
//! status header, the return value (`SoterErrorCode`, i.e. an `int32`, except
//! `initSign` which returns the `SoterInitReturn` parcelable), then the out
//! parameters.
//!
//! The reply shapes are pinned to byte-level captures from the live HAL; see
//! `tests::reply_bytes_match_captured_hal_failures`.

/// Interface token every Soter client writes.
pub const SOTER_INTERFACE: &str = "vendor.qti.hardware.soter.ISoter";

/// The `<descriptor>/default` spelling some tools write.
pub const SOTER_INTERFACE_INSTANCE: &str = "vendor.qti.hardware.soter.ISoter/default";

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

/// Cursor over the argument section of a request parcel.
pub struct Args<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Args<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Split a request parcel into its interface token and the argument cursor.
    pub fn parse_request(buf: &'a [u8]) -> Option<(String, Self)> {
        let mut args = Self::new(buf);
        args.read_i32()?; // strict-mode policy word
        let token = args.read_string16()?;
        Some((token, args))
    }

    /// True for both token spellings seen in the wild.
    pub fn is_soter_token(token: &str) -> bool {
        token == SOTER_INTERFACE || token == SOTER_INTERFACE_INSTANCE
    }

    pub fn read_i32(&mut self) -> Option<i32> {
        let bytes = self.buf.get(self.pos..self.pos.checked_add(4)?)?;
        self.pos += 4;
        Some(i32::from_le_bytes(bytes.try_into().ok()?))
    }

    pub fn read_u32(&mut self) -> Option<u32> {
        self.read_i32().map(|value| value as u32)
    }

    pub fn read_i64(&mut self) -> Option<i64> {
        let bytes = self.buf.get(self.pos..self.pos.checked_add(8)?)?;
        self.pos += 8;
        Some(i64::from_le_bytes(bytes.try_into().ok()?))
    }

    /// AIDL `byte` occupies a signed 32-bit parcel word.
    pub fn read_byte(&mut self) -> Option<i8> {
        self.read_i32()?.try_into().ok()
    }

    /// `byte[]`: length, data, padding. A negative length means a null array.
    pub fn read_byte_array(&mut self) -> Option<Vec<u8>> {
        let len = self.read_i32()?;
        if len < 0 {
            return Some(Vec::new());
        }
        let len = len as usize;
        self.buf.get(self.pos..self.pos.checked_add(align4(len))?)?;
        let bytes = self.buf.get(self.pos..self.pos.checked_add(len)?)?.to_vec();
        self.pos += align4(len);
        Some(bytes)
    }

    /// `string16`: length in code units, UTF-16LE data, NUL, padding.
    pub fn read_string16(&mut self) -> Option<String> {
        let len = self.read_i32()?;
        if len < 0 {
            return None;
        }
        let len = len as usize;
        let byte_len = len.checked_mul(2)?;
        let padded_len = align4(byte_len.checked_add(2)?);
        self.buf.get(self.pos..self.pos.checked_add(padded_len)?)?;
        let end = self.pos.checked_add(byte_len)?;
        if self.buf.get(end..end.checked_add(2)?)? != [0, 0] {
            return None;
        }
        let raw = self.buf.get(self.pos..end)?;
        // An explicit index loop instead of `chunks_exact(2)`: that helper is a
        // clippy lint target (`chunks_exact_to_as_chunks`) on the pinned nightly,
        // and the wire length is exactly `len` code units here.
        let mut units = Vec::with_capacity(len);
        for index in 0..len {
            let pair = raw.get(index * 2..index * 2 + 2)?;
            units.push(u16::from_le_bytes([pair[0], pair[1]]));
        }
        self.pos += padded_len;
        String::from_utf16(&units).ok()
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

/// Reply builder. The status header is written first, always.
pub struct Reply {
    bytes: Vec<u8>,
}

impl Reply {
    /// `writeNoException`: nothing went wrong at the binder level.
    pub fn ok() -> Self {
        Self::with_header(0)
    }

    /// An exception status: code plus message.
    pub fn exception(code: i32, message: &str) -> Self {
        let mut reply = Self::with_header(code);
        reply.string16(message);
        reply
    }

    fn with_header(code: i32) -> Self {
        let mut reply = Self {
            bytes: Vec::with_capacity(64),
        };
        reply.i32(code);
        reply
    }

    pub fn i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn byte_array(&mut self, value: &[u8]) {
        self.i32(value.len() as i32);
        self.bytes.extend_from_slice(value);
        while !self.bytes.len().is_multiple_of(4) {
            self.bytes.push(0);
        }
    }

    pub fn string16(&mut self, value: &str) {
        let units: Vec<u16> = value.encode_utf16().collect();
        self.i32(units.len() as i32);
        for unit in &units {
            self.bytes.extend_from_slice(&unit.to_le_bytes());
        }
        self.bytes.extend_from_slice(&0u16.to_le_bytes());
        while !self.bytes.len().is_multiple_of(4) {
            self.bytes.push(0);
        }
    }

    /// `SoterBufferReturn` as an out parameter: presence word, then
    /// `[size][byte[] buffer][int32 field]`.
    ///
    /// The stock HAL writes a *present* but empty structure even when the call
    /// fails (`-20`), so the presence word stays `1` for every reply and the
    /// result travels in the return code.
    pub fn buffer_return(&mut self, buffer: &[u8], field: i32) {
        self.i32(1);
        let size = 4 + 4 + align4(buffer.len()) + 4;
        self.i32(size as i32);
        self.byte_array(buffer);
        self.i32(field);
    }

    /// `SoterInitReturn`, returned by value: presence word, then
    /// `[size = 16][int32 code][int64 session]`.
    pub fn init_return(&mut self, code: i32, session: i64) {
        self.i32(1);
        self.i32(16);
        self.i32(code);
        self.i64(session);
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_array_requires_its_padding_and_string_requires_nul() {
        let truncated_array = [1, 0, 0, 0, 0xa5];
        assert!(Args::new(&truncated_array).read_byte_array().is_none());
        let valid_array = [1, 0, 0, 0, 0xa5, 0, 0, 0];
        assert_eq!(Args::new(&valid_array).read_byte_array(), Some(vec![0xa5]));

        for malformed in [
            &[0, 0, 0, 0][..],
            &[0, 0, 0, 0, 0, 0][..],
            &[0, 0, 0, 0, 1, 0, 0, 0][..],
            &[1, 0, 0, 0, b'a', 0][..],
        ] {
            assert!(Args::new(malformed).read_string16().is_none());
        }
        assert_eq!(
            Args::new(&[0, 0, 0, 0, 0, 0, 0, 0]).read_string16(),
            Some(String::new())
        );
    }
}
