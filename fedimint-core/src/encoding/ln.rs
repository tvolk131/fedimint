use std::io::Error;

use lightning::util::ser::{BigSize, Readable, Writeable};

use crate::encoding::{CountWrite, Decodable, DecodeError, Encodable, SimpleBitcoinRead};
use crate::module::registry::ModuleDecoderRegistry;

impl Encodable for lightning_invoice::Bolt11Invoice {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.to_string().consensus_encode(writer)
    }
}

impl Decodable for lightning_invoice::Bolt11Invoice {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        String::consensus_decode(d, modules)?
            .parse::<Self>()
            .map_err(DecodeError::from_err)
    }
}

impl Encodable for lightning_invoice::RoutingFees {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.base_msat.consensus_encode(writer)?;
        len += self.proportional_millionths.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for lightning_invoice::RoutingFees {
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let base_msat = Decodable::consensus_decode(d, modules)?;
        let proportional_millionths = Decodable::consensus_decode(d, modules)?;
        Ok(Self {
            base_msat,
            proportional_millionths,
        })
    }
}

impl Encodable for BigSize {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut writer = CountWrite::from(writer);
        self.write(&mut writer)?;
        Ok(usize::try_from(writer.count()).expect("can't overflow"))
    }
}

impl Decodable for BigSize {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Self::read(&mut SimpleBitcoinRead(r))
            .map_err(|e| DecodeError::new_custom(anyhow::anyhow!("BigSize decoding error: {e:?}")))
    }
}

#[cfg(test)]
mod tests {
    use crate::encoding::tests::test_roundtrip;

    #[test_log::test]
    fn bolt11_invoice_roundtrip() {
        let invoice_str = "lnbc100p1psj9jhxdqud3jxktt5w46x7unfv9kz6mn0v3jsnp4q0d3p2sfluzdx45tqcs\
			h2pu5qc7lgq0xs578ngs6s0s68ua4h7cvspp5q6rmq35js88zp5dvwrv9m459tnk2zunwj5jalqtyxqulh0l\
			5gflssp5nf55ny5gcrfl30xuhzj3nphgj27rstekmr9fw3ny5989s300gyus9qyysgqcqpcrzjqw2sxwe993\
			h5pcm4dxzpvttgza8zhkqxpgffcrf5v25nwpr3cmfg7z54kuqq8rgqqqqqqqq2qqqqq9qq9qrzjqd0ylaqcl\
			j9424x9m8h2vcukcgnm6s56xfgu3j78zyqzhgs4hlpzvznlugqq9vsqqqqqqqlgqqqqqeqq9qrzjqwldmj9d\
			ha74df76zhx6l9we0vjdquygcdt3kssupehe64g6yyp5yz5rhuqqwccqqyqqqqlgqqqqjcqq9qrzjqf9e58a\
			guqr0rcun0ajlvmzq3ek63cw2w282gv3z5uupmuwvgjtq2z55qsqqg6qqqyqqqrtnqqqzq3cqygrzjqvphms\
			ywntrrhqjcraumvc4y6r8v4z5v593trte429v4hredj7ms5z52usqq9ngqqqqqqqlgqqqqqqgq9qrzjq2v0v\
			p62g49p7569ev48cmulecsxe59lvaw3wlxm7r982zxa9zzj7z5l0cqqxusqqyqqqqlgqqqqqzsqygarl9fh3\
			8s0gyuxjjgux34w75dnc6xp2l35j7es3jd4ugt3lu0xzre26yg5m7ke54n2d5sym4xcmxtl8238xxvw5h5h5\
			j5r6drg6k6zcqj0fcwg";
        let invoice = invoice_str
            .parse::<lightning_invoice::Bolt11Invoice>()
            .unwrap();
        test_roundtrip(&invoice);
    }
}
