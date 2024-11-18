use std::borrow::Cow;
use std::io::{Error, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use lightning::util::ser::BigSize;

use super::DynEncodable;
use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;
use crate::util::SafeUrl;

impl Encodable for SafeUrl {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_string().consensus_encode(writer)
    }
}

impl Decodable for SafeUrl {
    fn consensus_decode_from_finite_reader<D: Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        String::consensus_decode_from_finite_reader(d, modules)?
            .parse::<Self>()
            .map_err(DecodeError::from_err)
    }
}

impl Encodable for () {
    fn consensus_encode<W: Write>(&self, _writer: &mut W) -> Result<usize, Error> {
        Ok(0)
    }
}

impl Decodable for () {
    fn consensus_decode<D: Read>(
        _d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(())
    }
}

impl Encodable for &str {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.as_bytes().consensus_encode(writer)
    }
}

impl Encodable for String {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.as_bytes().consensus_encode(writer)
    }
}

impl Decodable for String {
    fn consensus_decode_from_finite_reader<D: Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::from_utf8(Decodable::consensus_decode_from_finite_reader(d, modules)?)
            .map_err(DecodeError::from_err)
    }
}

impl Encodable for Cow<'static, str> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.as_ref().consensus_encode(writer)
    }
}

impl Decodable for Cow<'static, str> {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Cow::Owned(String::consensus_decode(d, modules)?))
    }
}

impl Encodable for SystemTime {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let duration = self.duration_since(UNIX_EPOCH).expect("valid duration");
        duration.consensus_encode_dyn(writer)
    }
}

impl Decodable for SystemTime {
    fn consensus_decode<D: Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let duration = Duration::consensus_decode(d, modules)?;
        Ok(UNIX_EPOCH + duration)
    }
}

impl Encodable for Duration {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut count = 0;
        count += self.as_secs().consensus_encode(writer)?;
        count += self.subsec_nanos().consensus_encode(writer)?;

        Ok(count)
    }
}

impl Decodable for Duration {
    fn consensus_decode<D: Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let secs = Decodable::consensus_decode(d, modules)?;
        let nsecs = Decodable::consensus_decode(d, modules)?;
        Ok(Self::new(secs, nsecs))
    }
}

impl Encodable for bool {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let bool_as_u8 = u8::from(*self);
        writer.write_all(&[bool_as_u8])?;
        Ok(1)
    }
}

impl Decodable for bool {
    fn consensus_decode<D: Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bool_as_u8 = [0u8];
        d.read_exact(&mut bool_as_u8)
            .map_err(DecodeError::from_err)?;
        match bool_as_u8[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::from_str("Out of range, expected 0 or 1")),
        }
    }
}

macro_rules! impl_encode_decode_num_as_bigsize {
    ($num_type:ty) => {
        impl Encodable for $num_type {
            fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
                BigSize(u64::from(*self)).consensus_encode(writer)
            }
        }

        impl Decodable for $num_type {
            fn consensus_decode<D: std::io::Read>(
                d: &mut D,
                _modules: &ModuleDecoderRegistry,
            ) -> Result<Self, crate::encoding::DecodeError> {
                let varint = BigSize::consensus_decode(d, &Default::default())
                    .context(concat!("VarInt inside ", stringify!($num_type)))?;
                <$num_type>::try_from(varint.0).map_err(crate::encoding::DecodeError::from_err)
            }
        }
    };
}

macro_rules! impl_encode_decode_num_as_plain {
    ($num_type:ty) => {
        impl Encodable for $num_type {
            fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
                let bytes = self.to_be_bytes();
                writer.write_all(&bytes[..])?;
                Ok(bytes.len())
            }
        }

        impl Decodable for $num_type {
            fn consensus_decode<D: std::io::Read>(
                d: &mut D,
                _modules: &ModuleDecoderRegistry,
            ) -> Result<Self, crate::encoding::DecodeError> {
                let mut bytes = [0u8; (<$num_type>::BITS / 8) as usize];
                d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
                Ok(<$num_type>::from_be_bytes(bytes))
            }
        }
    };
}

impl_encode_decode_num_as_bigsize!(u64);
impl_encode_decode_num_as_bigsize!(u32);
impl_encode_decode_num_as_bigsize!(u16);
impl_encode_decode_num_as_plain!(u8);

#[cfg(test)]
mod tests {
    use crate::encoding::tests::test_roundtrip;

    #[test_log::test]
    fn test_systemtime() {
        test_roundtrip(&fedimint_core::time::now());
    }
}
