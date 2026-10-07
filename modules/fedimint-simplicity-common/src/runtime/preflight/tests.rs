use simplicity::{BitWriter, encode};

use super::check;

#[test]
fn every_node_form_leaves_the_cursor_at_the_next_node() {
    // Literal wire tags, independent of the production scanner. References are
    // distance one (encoded 0); structural scanning does not check DAG types.
    let mut forms = vec![
        "0000000".to_owned(),     // comp
        "0000100".to_owned(),     // case
        "0001000".to_owned(),     // pair
        "0001100".to_owned(),     // disconnect
        "001000".to_owned(),      // injl
        "001010".to_owned(),      // injr
        "001100".to_owned(),      // take
        "001110".to_owned(),      // drop
        "01000".to_owned(),       // iden
        "01001".to_owned(),       // unit
        "010110".to_owned(),      // disconnect1
        "0111".to_owned(),        // witness
        "11100000000".to_owned(), // context jet: sig_hash_all
        "1001".to_owned(),        // constant one-bit word
    ];
    forms.push(format!("01010{}", "1".repeat(512))); // fail
    forms.push(format!("0110{}", "1".repeat(256))); // hidden
    for form in forms {
        for complete in [true, false] {
            let mut bytes = Vec::new();
            let mut bits = BitWriter::new(&mut bytes);
            encode::encode_natural(3, &mut bits).unwrap();
            bits.write_bits_be(0b01001, 5).unwrap(); // first node: unit
            for bit in form.bytes() {
                bits.write_bit(bit == b'1').unwrap();
            }
            bits.write_bits_be(0b10, 2).unwrap();
            encode::encode_natural(5, &mut bits).unwrap(); // 16-bit word
            if complete {
                bits.write_bits_be(0xabcd, 16).unwrap();
            }
            bits.flush_all().unwrap();
            assert_eq!(check(&bytes).is_ok(), complete, "node {form}");
        }
    }
}
