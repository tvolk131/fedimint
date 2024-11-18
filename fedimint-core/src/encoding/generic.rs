use std::any::TypeId;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;
use std::io::Error;

use anyhow::format_err;

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::{ModuleDecoderRegistry, ModuleRegistry};

macro_rules! impl_encode_decode_tuple {
    ($($x:ident),*) => (
        #[allow(non_snake_case)]
        impl <$($x: Encodable),*> Encodable for ($($x),*) {
            fn consensus_encode<W: std::io::Write>(&self, s: &mut W) -> Result<usize, std::io::Error> {
                let &($(ref $x),*) = self;
                let mut len = 0;
                $(len += $x.consensus_encode(s)?;)*
                Ok(len)
            }
        }

        #[allow(non_snake_case)]
        impl<$($x: Decodable),*> Decodable for ($($x),*) {
            fn consensus_decode<D: std::io::Read>(d: &mut D, modules: &ModuleDecoderRegistry) -> Result<Self, DecodeError> {
                Ok(($({let $x = Decodable::consensus_decode(d, modules)?; $x }),*))
            }
        }
    );
}

impl_encode_decode_tuple!(T1, T2);
impl_encode_decode_tuple!(T1, T2, T3);
impl_encode_decode_tuple!(T1, T2, T3, T4);

impl<T> Encodable for &[T]
where
    T: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            // unsafe: we've just checked that T is `u8` so the transmute here is a no-op
            return consensus_encode_bytes(
                unsafe { std::mem::transmute::<&[T], &[u8]>(self) },
                writer,
            );
        }

        let mut len = 0;
        len += (self.len() as u64).consensus_encode(writer)?;

        for item in *self {
            len += item.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<T> Encodable for Vec<T>
where
    T: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        (self as &[T]).consensus_encode(writer)
    }
}

impl<T> Decodable for Vec<T>
where
    T: Decodable + 'static,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            // unsafe: we've just checked that T is `u8` so the transmute here is a no-op
            return Ok(unsafe {
                std::mem::transmute::<Vec<u8>, Self>(consensus_decode_bytes_from_finite_reader(d)?)
            });
        }
        let len = u64::consensus_decode_from_finite_reader(d, modules)?;

        // `collect` under the hood uses `FromIter::from_iter`, which can potentially be
        // backed by code like:
        // <https://github.com/rust-lang/rust/blob/fe03b46ee4688a99d7155b4f9dcd875b6903952d/library/alloc/src/vec/spec_from_iter_nested.rs#L31>
        // This can take `size_hint` from input iterator and pre-allocate memory
        // upfront with `Vec::with_capacity`. Because of that untrusted `len`
        // should not be used directly.
        let cap_len = std::cmp::min(8_000 / std::mem::size_of::<T>() as u64, len);

        // Up to a cap, use the (potentially specialized for better perf in stdlib)
        // `from_iter`.
        let mut v: Self = (0..cap_len)
            .map(|_| T::consensus_decode_from_finite_reader(d, modules))
            .collect::<Result<Self, DecodeError>>()?;

        // Add any excess manually avoiding any surprises.
        while (v.len() as u64) < len {
            v.push(T::consensus_decode_from_finite_reader(d, modules)?);
        }

        assert_eq!(v.len() as u64, len);

        Ok(v)
    }
}

struct ReadBytesFromFiniteReaderOpts {
    len: usize,
    chunk_size: usize,
}

/// Specialized version of Decodable for bytes
fn consensus_decode_bytes_from_finite_reader<D: std::io::Read>(
    r: &mut D,
) -> Result<Vec<u8>, DecodeError> {
    let len = u64::consensus_decode_from_finite_reader(r, &ModuleRegistry::default())?;

    let len: usize =
        usize::try_from(len).map_err(|_| DecodeError::from_str("size exceeds memory"))?;

    let opts = ReadBytesFromFiniteReaderOpts {
        len,
        chunk_size: 64 * 1024,
    };

    read_bytes_from_finite_reader(r, opts).map_err(DecodeError::from_err)
}

/// Read `opts.len` bytes from reader, where `opts.len` could potentially be
/// malicious.
///
/// Adapted from <https://github.com/rust-bitcoin/rust-bitcoin/blob/e2b9555070d9357fb552e56085fb6fb3f0274560/bitcoin/src/consensus/encode.rs#L659>
#[inline]
fn read_bytes_from_finite_reader<D: std::io::Read + ?Sized>(
    d: &mut D,
    mut opts: ReadBytesFromFiniteReaderOpts,
) -> Result<Vec<u8>, std::io::Error> {
    let mut ret = vec![];

    assert_ne!(opts.chunk_size, 0);

    while opts.len > 0 {
        let chunk_start = ret.len();
        let chunk_size = core::cmp::min(opts.len, opts.chunk_size);
        let chunk_end = chunk_start + chunk_size;
        ret.resize(chunk_end, 0u8);
        d.read_exact(&mut ret[chunk_start..chunk_end])?;
        opts.len -= chunk_size;
    }

    Ok(ret)
}

impl<T> Encodable for std::ops::RangeInclusive<T>
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        (self.start(), self.end()).consensus_encode(writer)
    }
}

impl<T> Decodable for std::ops::RangeInclusive<T>
where
    T: Decodable,
{
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        let r = <(T, T)>::consensus_decode(d, &ModuleRegistry::default())?;
        Ok(Self::new(r.0, r.1))
    }
}

impl<K, V> Encodable for BTreeMap<K, V>
where
    K: Encodable,
    V: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += (self.len() as u64).consensus_encode(writer)?;
        for (k, v) in self {
            len += k.consensus_encode(writer)?;
            len += v.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<K, V> Decodable for BTreeMap<K, V>
where
    K: Decodable + Ord,
    V: Decodable,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut res = Self::new();
        let len = u64::consensus_decode_from_finite_reader(d, modules)?;
        for _ in 0..len {
            let k = K::consensus_decode_from_finite_reader(d, modules)?;
            if res
                .last_key_value()
                .is_some_and(|(prev_key, _v)| k <= *prev_key)
            {
                return Err(DecodeError::from_str("Non-canonical encoding"));
            }
            let v = V::consensus_decode_from_finite_reader(d, modules)?;
            if res.insert(k, v).is_some() {
                return Err(DecodeError(format_err!("Duplicate key")));
            }
        }
        Ok(res)
    }
}

impl<K> Encodable for BTreeSet<K>
where
    K: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += (self.len() as u64).consensus_encode(writer)?;
        for k in self {
            len += k.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<K> Decodable for BTreeSet<K>
where
    K: Decodable + Ord,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut res = Self::new();
        let len = u64::consensus_decode_from_finite_reader(d, modules)?;
        for _ in 0..len {
            let k = K::consensus_decode_from_finite_reader(d, modules)?;
            if res.last().is_some_and(|prev_key| k <= *prev_key) {
                return Err(DecodeError::from_str("Non-canonical encoding"));
            }
            if !res.insert(k) {
                return Err(DecodeError(format_err!("Duplicate key")));
            }
        }
        Ok(res)
    }
}

impl<T> Encodable for VecDeque<T>
where
    T: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = (self.len() as u64).consensus_encode(writer)?;
        for i in self {
            len += i.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<T> Decodable for VecDeque<T>
where
    T: Decodable + 'static,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::from(Vec::<T>::consensus_decode_from_finite_reader(
            d, modules,
        )?))
    }
}

impl<T, const SIZE: usize> Encodable for [T; SIZE]
where
    T: Encodable + 'static,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            // unsafe: we've just checked that T is `u8` so the transmute here is a no-op
            return consensus_encode_bytes_static(
                unsafe { std::mem::transmute::<&[T; SIZE], &[u8; SIZE]>(self) },
                writer,
            );
        }

        let mut len = 0;
        for item in self {
            len += item.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<T, const SIZE: usize> Decodable for [T; SIZE]
where
    T: Decodable + Debug + Default + Copy + 'static,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            // unsafe: we've just checked that T is `u8` so the transmute here is a no-op
            return Ok(unsafe {
                let arr = consensus_decode_bytes_static_from_finite_reader(d)?;
                horribe_array_transmute_workaround::<SIZE, u8, T>(arr)
            });
        }
        // todo: impl without copy
        let mut data = [T::default(); SIZE];
        for item in &mut data {
            *item = T::consensus_decode_from_finite_reader(d, modules)?;
        }
        Ok(data)
    }
}

impl<T> Encodable for Option<T>
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        if let Some(inner) = self {
            len += 1u8.consensus_encode(writer)?;
            len += inner.consensus_encode(writer)?;
        } else {
            len += 0u8.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl<T> Decodable for Option<T>
where
    T: Decodable,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let flag = u8::consensus_decode_from_finite_reader(d, modules)?;
        match flag {
            0 => Ok(None),
            1 => Ok(Some(T::consensus_decode_from_finite_reader(d, modules)?)),
            _ => Err(DecodeError::from_str(
                "Invalid flag for option enum, expected 0 or 1",
            )),
        }
    }
}

impl<T, E> Encodable for Result<T, E>
where
    T: Encodable,
    E: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;

        match self {
            Ok(value) => {
                len += 1u8.consensus_encode(writer)?;
                len += value.consensus_encode(writer)?;
            }
            Err(error) => {
                len += 0u8.consensus_encode(writer)?;
                len += error.consensus_encode(writer)?;
            }
        }

        Ok(len)
    }
}

impl<T, E> Decodable for Result<T, E>
where
    T: Decodable,
    E: Decodable,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let flag = u8::consensus_decode_from_finite_reader(d, modules)?;
        match flag {
            0 => Ok(Err(E::consensus_decode_from_finite_reader(d, modules)?)),
            1 => Ok(Ok(T::consensus_decode_from_finite_reader(d, modules)?)),
            _ => Err(DecodeError::from_str(
                "Invalid flag for option enum, expected 0 or 1",
            )),
        }
    }
}

impl<T> Encodable for Box<T>
where
    T: Encodable,
{
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.as_ref().consensus_encode(writer)
    }
}

impl<T> Decodable for Box<T>
where
    T: Decodable,
{
    fn consensus_decode_from_finite_reader<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self::new(T::consensus_decode_from_finite_reader(
            d, modules,
        )?))
    }
}

/// Specialized version of Encodable for bytes
fn consensus_encode_bytes<W: std::io::Write>(bytes: &[u8], writer: &mut W) -> Result<usize, Error> {
    let mut len = 0;
    len += (bytes.len() as u64).consensus_encode(writer)?;
    writer.write_all(bytes)?;
    len += bytes.len();
    Ok(len)
}

/// Specialized version of Encodable for static byte arrays
fn consensus_encode_bytes_static<const N: usize, W: std::io::Write>(
    bytes: &[u8; N],
    writer: &mut W,
) -> Result<usize, Error> {
    writer.write_all(bytes)?;
    Ok(bytes.len())
}

/// Specialized version of Decodable for fixed-size byte arrays
fn consensus_decode_bytes_static_from_finite_reader<const N: usize, D: std::io::Read>(
    r: &mut D,
) -> Result<[u8; N], DecodeError> {
    let mut bytes = [0u8; N];
    r.read_exact(bytes.as_mut_slice())
        .map_err(DecodeError::from_err)?;
    Ok(bytes)
}

// From <https://github.com/rust-lang/rust/issues/61956>
unsafe fn horribe_array_transmute_workaround<const N: usize, A, B>(mut arr: [A; N]) -> [B; N] {
    let ptr = std::ptr::from_mut(&mut arr).cast::<[B; N]>();
    let res = ptr.read();
    core::mem::forget(arr);
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::tests::test_roundtrip;
    use crate::encoding::Decodable;
    use crate::module::registry::ModuleRegistry;

    #[test_log::test]
    fn vec_decode_sanity() {
        let buf = [
            0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0,
        ];

        // On malicious large len, return an error instead of panicking.
        assert!(
            Vec::<u8>::consensus_decode(&mut buf.as_slice(), &ModuleRegistry::default()).is_err()
        );
        assert!(
            Vec::<u16>::consensus_decode(&mut buf.as_slice(), &ModuleRegistry::default()).is_err()
        );
    }

    #[test_log::test]
    fn vec_deque_decode_sanity() {
        let buf = [
            0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0,
        ];

        // On malicious large len, return an error instead of panicking.
        assert!(
            VecDeque::<u8>::consensus_decode(&mut buf.as_slice(), &ModuleRegistry::default())
                .is_err()
        );
        assert!(
            VecDeque::<u16>::consensus_decode(&mut buf.as_slice(), &ModuleRegistry::default())
                .is_err()
        );
    }

    #[test_log::test]
    fn test_btreemap() {
        test_roundtrip(&BTreeMap::from([
            ("a".to_string(), 1u32),
            ("b".to_string(), 2),
        ]));
    }

    #[test_log::test]
    fn test_btreeset() {
        test_roundtrip(&BTreeSet::from(["a".to_string(), "b".to_string()]));
    }
}
