//! Read a non-stable AIDL transaction constant from the installed system DEX.
//! No framework code is executed and no transaction number is probed.
use std::{fs::File, io::Read, sync::OnceLock};

use anyhow::{anyhow, bail, Context, Result};

const STUB: &str = "Landroid/app/IActivityManager$Stub;";
const FIELD: &str = "TRANSACTION_getRunningAppProcesses";
const MAX_DEX_SIZE: u64 = 128 * 1024 * 1024;

pub(super) fn running_processes_transaction() -> Result<u32> {
    static CODE: OnceLock<std::result::Result<u32, String>> = OnceLock::new();
    CODE.get_or_init(|| read_framework().map_err(|error| format!("{error:#}")))
        .clone()
        .map_err(|error| anyhow!(error))
}

fn read_framework() -> Result<u32> {
    let mut archive = zip::ZipArchive::new(File::open("/system/framework/framework.jar")?)?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let name = file.name()?;
        if !(name == "classes.dex"
            || name.strip_prefix("classes").and_then(|tail| tail.strip_suffix(".dex")).is_some_and(
                |number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()),
            ))
        {
            continue;
        }
        if file.size() > MAX_DEX_SIZE {
            bail!("framework DEX exceeds size limit");
        }
        let mut data = Vec::with_capacity(file.size() as usize);
        (&mut file).take(MAX_DEX_SIZE + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_DEX_SIZE {
            bail!("expanded framework DEX exceeds size limit");
        }
        if let Some(code) = Dex::new(&data)?.transaction()? {
            return Ok(code);
        }
    }
    bail!("ActivityManager transaction constant absent from system framework")
}

struct Dex<'a> {
    data: &'a [u8],
}

impl<'a> Dex<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() < 112
            || &data[..4] != b"dex\n"
            || data[7] != 0
            || !matches!(&data[4..7], b"035" | b"037" | b"038" | b"039" | b"040")
        {
            bail!("unsupported framework DEX header");
        }
        let dex = Self { data };
        if dex.u32(32)? as usize != data.len() || dex.u32(36)? != 112 || dex.u32(40)? != 0x12345678
        {
            bail!("invalid framework DEX boundaries or byte order");
        }
        Ok(dex)
    }

    fn bytes(&self, offset: usize, len: usize) -> Result<&'a [u8]> {
        let end = offset.checked_add(len).context("DEX offset overflow")?;
        self.data.get(offset..end).context("truncated framework DEX")
    }

    fn u16(&self, offset: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(self.bytes(offset, 2)?.try_into()?))
    }

    fn u32(&self, offset: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(offset, 4)?.try_into()?))
    }

    fn byte(&self, cursor: &mut usize) -> Result<u8> {
        let value = self.bytes(*cursor, 1)?[0];
        *cursor += 1;
        Ok(value)
    }

    fn uleb(&self, cursor: &mut usize) -> Result<u32> {
        let mut value = 0;
        for shift in (0..35).step_by(7) {
            let byte = self.byte(cursor)?;
            if shift == 28 && byte > 0x0f {
                bail!("DEX ULEB overflow");
            }
            value |= u32::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        bail!("unterminated DEX ULEB")
    }

    fn table(&self, header: usize, width: usize, index: u32) -> Result<usize> {
        let count = self.u32(header)?;
        if index >= count {
            bail!("DEX table index out of bounds");
        }
        let base = self.u32(header + 4)? as usize;
        let size = (count as usize).checked_mul(width).context("DEX table size overflow")?;
        self.bytes(base, size)?;
        Ok(base + index as usize * width)
    }

    fn string_is(&self, index: u32, expected: &str) -> Result<bool> {
        let mut cursor = self.u32(self.table(56, 4, index)?)? as usize;
        let utf16_length = self.uleb(&mut cursor)? as usize;
        // Both names being matched are ASCII, also represented literally in MUTF-8.
        if utf16_length != expected.len() {
            return Ok(false);
        }
        Ok(self.bytes(cursor, expected.len() + 1)? == [expected.as_bytes(), &[0]].concat())
    }

    fn type_is(&self, index: u32, expected: &str) -> Result<bool> {
        self.string_is(self.u32(self.table(64, 4, index)?)?, expected)
    }

    fn transaction(&self) -> Result<Option<u32>> {
        for index in 0..self.u32(96)? {
            let definition = self.table(96, 32, index)?;
            let class = self.u32(definition)?;
            if !self.type_is(class, STUB)? {
                continue;
            }
            let mut cursor = self.u32(definition + 24)? as usize;
            if cursor == 0 {
                bail!("ActivityManager Stub has no class data");
            }
            let count = self.uleb(&mut cursor)?;
            if count > self.u32(80)? {
                bail!("invalid static field count");
            }
            for _ in 0..3 {
                self.uleb(&mut cursor)?;
            }
            let mut field_index = 0u32;
            let mut wanted = None;
            for position in 0..count {
                field_index = field_index
                    .checked_add(self.uleb(&mut cursor)?)
                    .context("field index overflow")?;
                let flags = self.uleb(&mut cursor)?;
                let field = self.table(80, 8, field_index)?;
                if u32::from(self.u16(field)?) == class
                    && self.string_is(self.u32(field + 4)?, FIELD)?
                {
                    if flags & 0x18 != 0x18
                        || !self.type_is(u32::from(self.u16(field + 2)?), "I")?
                    {
                        bail!("transaction field is not a static final int");
                    }
                    wanted = Some(position);
                }
            }
            let wanted = wanted.context("ActivityManager Stub lacks transaction field")?;
            let mut cursor = self.u32(definition + 28)? as usize;
            if cursor == 0 {
                bail!("transaction constant has no encoded value");
            }
            let values = self.uleb(&mut cursor)?;
            if values > count || wanted >= values {
                bail!("transaction constant is uninitialized");
            }
            for _ in 0..wanted {
                self.skip_value(&mut cursor, 0)?;
            }
            let header = self.byte(&mut cursor)?;
            let width = usize::from(header >> 5) + 1;
            if header & 0x1f != 0x04 || width > 4 {
                bail!("transaction constant is not an encoded int");
            }
            let raw = self.bytes(cursor, width)?;
            let mut integer = [if raw[width - 1] & 0x80 == 0 { 0 } else { 0xff }; 4];
            integer[..width].copy_from_slice(raw);
            let code = i32::from_le_bytes(integer);
            if !(1..=0x00ff_ffff).contains(&code) {
                bail!("invalid AIDL transaction constant");
            }
            return Ok(Some(code as u32));
        }
        Ok(None)
    }

    fn skip_value(&self, cursor: &mut usize, depth: u32) -> Result<()> {
        if depth > 16 {
            bail!("DEX value nesting limit");
        }
        let header = self.byte(cursor)?;
        let kind = header & 0x1f;
        let arg = header >> 5;
        let max = match kind {
            0x00 => 0,
            0x02 | 0x03 => 1,
            0x04 | 0x10 | 0x15..=0x1b => 3,
            0x06 | 0x11 => 7,
            0x1c..=0x1e => 0,
            0x1f => 1,
            _ => bail!("invalid DEX encoded value type"),
        };
        if arg > max {
            bail!("invalid DEX encoded value width");
        }
        match kind {
            0x1c | 0x1d => {
                if kind == 0x1d {
                    self.uleb(cursor)?;
                }
                let count = self.uleb(cursor)? as usize;
                if count > self.data.len().saturating_sub(*cursor) {
                    bail!("invalid DEX value count");
                }
                for _ in 0..count {
                    if kind == 0x1d {
                        self.uleb(cursor)?;
                    }
                    self.skip_value(cursor, depth + 1)?;
                }
            }
            0x1e | 0x1f => {}
            _ => {
                let len = usize::from(arg) + 1;
                self.bytes(*cursor, len)?;
                *cursor += len;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
